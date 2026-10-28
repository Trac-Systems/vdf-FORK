// Copyright 2018 POA Networks Ltd.
// Modifications copyright 2026 Trac Systems.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::proof_of_time::serialize;
use super::progress::{ProgressReporter, SolvePhase, SolveProgress};
use classgroup::{gmp_classgroup::GmpClassGroup, BigNum, BigNumExt, ClassGroup};
use sha2::{digest::FixedOutput, Digest, Sha256};
use std::{cmp::Eq, collections::HashMap, hash::Hash, mem};

#[derive(Debug, Clone)]
pub struct WesolowskiVDF {
    discriminant_size_bits: u16,
}
use super::InvalidIterations as Bad;

impl WesolowskiVDF {
    /// Computes the same proof as `solve`, reporting completed work synchronously.
    /// Counts are cumulative within each phase of this invocation.
    pub fn solve_with_progress(
        &self,
        challenge: &[u8],
        difficulty: u64,
        observer: &mut dyn FnMut(SolveProgress),
    ) -> Result<Vec<u8>, Bad> {
        if difficulty > usize::MAX as u64 {
            return Err(Bad("Cannot have more that usize::MAX iterations".to_owned()));
        }
        let mut progress = ProgressReporter::new(Some(observer));
        Ok(create_proof_with_progress::<
            <GmpClassGroup as ClassGroup>::BigNum,
            GmpClassGroup,
        >(
            challenge,
            difficulty as usize,
            self.discriminant_size_bits,
            &mut progress,
        ))
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
pub struct WesolowskiVDFParams(pub u16);
impl super::VDFParams for WesolowskiVDFParams {
    type VDF = WesolowskiVDF;
    fn new(self) -> Self::VDF {
        WesolowskiVDF {
            discriminant_size_bits: self.0,
        }
    }
}

impl super::VDF for WesolowskiVDF {
    fn check_difficulty(&self, _difficulty: u64) -> Result<(), Bad> {
        Ok(())
    }
    fn solve(&self, challenge: &[u8], difficulty: u64) -> Result<Vec<u8>, Bad> {
        if difficulty > usize::MAX as u64 {
            Err(Bad("Cannot have more that usize::MAX iterations".to_owned()))
        } else {
            Ok(create_proof_of_time_wesolowski::<
                <GmpClassGroup as ClassGroup>::BigNum,
                GmpClassGroup,
            >(
                challenge,
                difficulty as usize,
                self.discriminant_size_bits,
            ))
        }
    }

    fn verify(
        &self,
        challenge: &[u8],
        difficulty: u64,
        alleged_solution: &[u8],
    ) -> Result<(), super::InvalidProof> {
        check_proof_of_time_wesolowski::<<GmpClassGroup as ClassGroup>::BigNum, GmpClassGroup>(
            challenge,
            alleged_solution,
            difficulty,
            self.discriminant_size_bits,
        )
        .map_err(|()| super::InvalidProof)
    }
}
/// To quote the original Python code:
///
/// > Create `L` and `k` parameters from papers, based on how many iterations
/// > need to be performed, and how much memory should be used.
pub fn approximate_parameters(t: f64) -> (usize, u8, u64) {
    let log_memory = (10_000_000.0f64).log2();
    let log_t = (t as f64).log2();
    let l = if log_t - log_memory > 0. {
        2.0f64.powf(log_memory - 20.).ceil()
    } else {
        1.
    };

    let intermediate = t * (2.0f64).ln() / (2.0 * l);
    let k = (intermediate.ln() - intermediate.ln().ln() + 0.25)
        .round()
        .max(1.);

    let w = (t / (t / k + l * (2.0f64).powf(k + 1.0)) - 2.0).floor();
    (l as _, k as _, w as _)
}

fn u64_to_bytes(q: u64) -> [u8; 8] {
    [
        (q >> 56) as u8,
        (q >> 48) as u8,
        (q >> 40) as u8,
        (q >> 32) as u8,
        (q >> 24) as u8,
        (q >> 16) as u8,
        (q >> 8) as u8,
        q as u8,
    ]
}

fn u16_to_bytes(q: u16) -> [u8; 2] {
    [(q >> 8) as u8, q as u8]
}

/// Quote:
///
/// > Creates a random prime based on input s.
fn hash_prime<T: BigNum>(seed: &[&[u8]]) -> T {
    hash_prime_with_progress(seed, &mut ProgressReporter::new(None))
}

fn hash_prime_with_progress<T: BigNum>(seed: &[&[u8]], progress: &mut ProgressReporter<'_>) -> T {
    let mut j = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.input(b"prime");
        hasher.input(u64_to_bytes(j));
        for i in seed {
            hasher.input(u64_to_bytes(i.len() as u64));
            hasher.input(i);
        }
        let n = T::from(&hasher.fixed_result()[..16]);
        let is_prime = n.probab_prime(2);
        progress.advance(SolvePhase::ChallengePrime, 1);
        if is_prime {
            progress.flush(SolvePhase::ChallengePrime);
            break n;
        }
        j += 1;
    }
}

/// Quote:
///
/// > Get“s the ith block of `2^T // B`, such that `sum(get_block(i) * 2^(k*i))
/// > = t^T // B`
fn get_block<T: BigNumExt>(i: u64, k: u8, t: u64, b: &T) -> T {
    let mut res = T::from(0);
    let two = T::from(2);
    res.mod_powm(&two, &T::from(t - u64::from(k) * (i + 1)), b);
    res *= &((two >> 1) << (k as usize));
    res / b
}

fn eval_optimized<T, U: BigNumExt, L: ClassGroup<BigNum = U> + Eq + Hash>(
    h: &L,
    b: &U,
    t: usize,
    k: u8,
    l: usize,
    powers: &T,
    progress: &mut ProgressReporter<'_>,
) -> L
where
    T: for<'a> std::ops::Index<&'a u64, Output = L>,
{
    assert!(k > 0, "k cannot be zero");
    assert!(l > 0, "l cannot be zero");
    let kl = (k as usize)
        .checked_mul(l)
        .expect("computing k*l overflowed a u64");
    assert!(kl <= u64::MAX as _);
    assert!((kl as u64) < (1u64 << 53), "k*l overflowed an f64");
    assert!((t as u64) < (1u64 << 53), "t overflows an f64");
    assert!(
        k < (mem::size_of::<usize>() << 3) as u8,
        "k must be less than the number of bits in a usize"
    );
    let k1 = k >> 1;
    let k0 = k - k1;
    let mut x = h.identity();
    let identity = h.identity();
    let k_exp = 1usize << k;
    let k0_exp = 1usize << k0;
    let k1_exp = 1usize << k1;
    for j in (0..l).rev() {
        x.pow(U::from(k_exp as u64));
        progress.advance(SolvePhase::ProofAggregation, 1);
        let mut ys: HashMap<U, L> = HashMap::new();
        for b in 0..1usize << k {
            ys.entry(U::from(b as u64))
                .or_insert_with(|| identity.clone());
            progress.advance(SolvePhase::ProofSetup, 1);
        }
        progress.flush(SolvePhase::ProofSetup);
        let end_of_loop = ((t as f64) / kl as f64).ceil() as usize;
        assert!(end_of_loop == 0 || (end_of_loop as u64 - 1).checked_mul(l as u64).is_some());
        for i in 0..end_of_loop {
            if t < k as usize * (i * l + j + 1) {
                continue;
            }
            // Cached powers supply 2^(k*i*l) the outer Horner loop supplies
            // 2^(k*j). Select the corresponding digit at index i*l+j.
            let b = get_block((i as u64) * (l as u64) + j as u64, k, t as _, b);
            *ys.get_mut(&b).unwrap() *= &powers[&((i * kl) as _)];
            progress.advance(SolvePhase::ProofBlocks, 1);
        }
        progress.flush(SolvePhase::ProofBlocks);

        for b1 in 0..k1_exp {
            let mut z = identity.clone();
            for b0 in 0..k0_exp {
                z *= &ys[&U::from((b1 * k0_exp + b0) as u64)];
                progress.advance(SolvePhase::ProofAggregation, 1);
            }
            z.pow(U::from((b1 as u64) * (k0_exp as u64)));
            x *= &z;
            progress.advance(SolvePhase::ProofAggregation, 2);
        }

        for b0 in 0..k0_exp {
            let mut z = identity.clone();
            for b1 in 0..k1_exp {
                z *= &ys[&U::from((b1 * k0_exp + b0) as u64)];
                progress.advance(SolvePhase::ProofAggregation, 1);
            }
            z.pow(U::from(b0 as u64));
            x *= &z;
            progress.advance(SolvePhase::ProofAggregation, 2);
        }
        progress.flush(SolvePhase::ProofAggregation);
    }
    x
}

pub fn generate_proof<U, T: BigNumExt, V: ClassGroup<BigNum = T> + Eq + Hash>(
    x: &V,
    challenge: &[u8],
    iterations: u64,
    discriminant_size_bits: u16,
    k: u8,
    l: usize,
    powers: &U,
) -> V
where
    U: for<'a> std::ops::Index<&'a u64, Output = V>,
{
    generate_proof_with_progress(
        x, challenge, iterations, discriminant_size_bits, k, l, powers,
        &mut ProgressReporter::new(None),
    )
}

fn generate_proof_with_progress<U, T: BigNumExt, V: ClassGroup<BigNum = T> + Eq + Hash>(
    x: &V,
    challenge: &[u8],
    iterations: u64,
    discriminant_size_bits: u16,
    k: u8,
    l: usize,
    powers: &U,
    progress: &mut ProgressReporter<'_>,
) -> V
where
    U: for<'a> std::ops::Index<&'a u64, Output = V>,
{
    let element_len = 2 * ((usize::from(discriminant_size_bits) + 16) >> 4);
    let mut y_buf = vec![0; element_len];
    powers[&iterations]
        .serialize(&mut y_buf[..])
        .expect(super::INCORRECT_BUFFER_SIZE);
    let iteration_bytes = u64_to_bytes(iterations);
    let size_bytes = u16_to_bytes(discriminant_size_bits);
    let discriminant_bytes = x.discriminant().to_bytes();
    let b = hash_prime_with_progress(
        &[challenge, &size_bytes, &iteration_bytes, &y_buf[..], &discriminant_bytes],
        progress,
    );
    eval_optimized(x, &b, iterations as _, k, l, powers, progress)
}

/// Verify a proof, according to the Wesolowski paper.
pub fn verify_proof<T: BigNum, V: ClassGroup<BigNum = T>>(
    challenge: &[u8],
    mut x: V,
    y: &V,
    mut proof: V,
    t: u64,
    discriminant_size_bits: u16,
) -> Result<(), ()> {
    let element_len = 2 * ((usize::from(discriminant_size_bits) + 16) >> 4);
    let mut y_buf = vec![0; element_len];
    y.serialize(&mut y_buf[..])
        .expect(super::INCORRECT_BUFFER_SIZE);
    let iteration_bytes = u64_to_bytes(t);
    let size_bytes = u16_to_bytes(discriminant_size_bits);
    let discriminant_bytes = x.discriminant().to_bytes();
    let b = hash_prime(&[challenge, &size_bytes, &iteration_bytes, &y_buf[..], &discriminant_bytes]);
    let mut r = T::from(0);
    r.mod_powm(&T::from(2u64), &T::from(t), &b);
    proof.pow(b);
    x.pow(r);
    proof *= &x;
    if &proof == y {
        Ok(())
    } else {
        Err(())
    }
}

pub fn create_proof_of_time_wesolowski<T: BigNumExt, V: ClassGroup<BigNum = T> + Eq + Hash>(
    challenge: &[u8],
    iterations: usize,
    discriminant_size_bits: u16,
) -> Vec<u8>
where
    for<'a, 'b> &'a V: std::ops::Mul<&'b V, Output = V>,
    for<'a, 'b> &'a V::BigNum: std::ops::Mul<&'b V::BigNum, Output = V::BigNum>,
{
    create_proof_with_progress::<T, V>(
        challenge, iterations, discriminant_size_bits, &mut ProgressReporter::new(None),
    )
}

fn create_proof_with_progress<T: BigNumExt, V: ClassGroup<BigNum = T> + Eq + Hash>(
    challenge: &[u8],
    iterations: usize,
    discriminant_size_bits: u16,
    progress: &mut ProgressReporter<'_>,
) -> Vec<u8>
where
    for<'a, 'b> &'a V: std::ops::Mul<&'b V, Output = V>,
    for<'a, 'b> &'a V::BigNum: std::ops::Mul<&'b V::BigNum, Output = V::BigNum>,
{
    let discriminant = super::create_discriminant::create_discriminant_with_progress(
        challenge, discriminant_size_bits, progress,
    );
    let x = V::from_ab_discriminant(2.into(), 1.into(), discriminant);
    assert!((iterations as u128) < (1u128 << 53));
    let (l, k, _) = approximate_parameters(iterations as f64);
    let q = l.checked_mul(k as _).expect("bug");
    let powers = super::proof_of_time::iterate_squarings_with_progress(
        x.clone(),
        (0..=iterations / q + 1)
            .map(|i| i * q)
            .chain(Some(iterations))
            .map(|x| x as _),
        progress,
    );
    let proof = if progress.enabled() {
        generate_proof_with_progress(
            &x, challenge, iterations as _, discriminant_size_bits, k, l, &powers, progress,
        )
    } else {
        generate_proof(&x, challenge, iterations as _, discriminant_size_bits, k, l, &powers)
    };
    let encoded = serialize(
        &[proof],
        &powers[&(iterations as _)],
        discriminant_size_bits.into(),
    );
    progress.advance(SolvePhase::Serialization, 1);
    encoded
}

pub fn check_proof_of_time_wesolowski<T: BigNum, V: ClassGroup<BigNum = T>>(
    challenge: &[u8],
    proof_blob: &[u8],
    iterations: u64,
    discriminant_size_bits: u16,
) -> Result<(), ()>
where
    T: BigNumExt,
{
    let discriminant: T =
        super::create_discriminant::create_discriminant(challenge, discriminant_size_bits);
    let x = V::from_ab_discriminant(2.into(), 1.into(), discriminant.clone());
    if (usize::MAX - 16) < discriminant_size_bits.into() {
        return Err(());
    }
    let int_size = (usize::from(discriminant_size_bits) + 16) >> 4;
    if int_size * 4 != proof_blob.len() {
        return Err(());
    }
    let (result_bytes, proof_bytes) = proof_blob.split_at(2 * int_size);
    let proof = ClassGroup::from_bytes(proof_bytes, discriminant.clone());
    let y = ClassGroup::from_bytes(result_bytes, discriminant);

    verify_proof(challenge, x, &y, proof, iterations, discriminant_size_bits)
}

#[cfg(test)]
mod large_difficulty_tests;

#[cfg(test)]
mod test {
    use super::*;
    use crate::{VDFParams, VDF};
    use classgroup::{gmp_classgroup::GmpClassGroup, ClassGroup};

    type G = GmpClassGroup;
    type Num = <G as ClassGroup>::BigNum;

    fn generator(challenge: &[u8], size_bits: u16) -> G {
        let d: Num = super::super::create_discriminant::create_discriminant(challenge, size_bits);
        G::from_ab_discriminant(2.into(), 1.into(), d)
    }

    fn powers_for(x: G, iterations: u64) -> std::collections::HashMap<u64, G> {
        let (l, k, _) = approximate_parameters(iterations as f64);
        let q = l.checked_mul(k as usize).expect("overflow");
        super::super::proof_of_time::iterate_squarings(
            x,
            (0..=iterations as usize / q + 1)
                .map(|i| (i * q) as u64)
                .chain(Some(iterations)),
        )
    }

    fn check_forced_parameters(l: usize, block_sizes: &[u8]) {
        // All T values exceed the 128-bit Fiat-Shamir prime's size, so the
        // expected proof exponent is nonzero. Cover complete and partial k*L
        // groups, odd/even k, several discriminants, and the production k=11.
        for challenge in [b"large-l-a".as_ref(), b"large-l-b", b"large-l-c"] {
            let size_bits = 512;
            let x = generator(challenge, size_bits);
            for iterations in [256u64, 257, 511] {
                for &k in block_sizes {
                    let stride = u64::from(k) * l as u64;
                    let powers = super::super::proof_of_time::iterate_squarings(
                        x.clone(),
                        (0..=iterations / stride + 1)
                            .map(|i| i * stride)
                            .chain(Some(iterations)),
                    );
                    let y = &powers[&iterations];
                    let mut y_bytes = vec![0; 2 * ((size_bits as usize + 16) >> 4)];
                    y.serialize(&mut y_bytes).unwrap();
                    let b: Num = hash_prime(&[
                        challenge,
                        &u16_to_bytes(size_bits),
                        &u64_to_bytes(iterations),
                        &y_bytes,
                        &x.discriminant().to_bytes(),
                    ]);
                    // Independent arithmetic oracle: no block extraction or
                    // optimized evaluator is used to compute floor(2^T / B).
                    let quotient = (Num::from(1u64) << iterations as usize) / &b;
                    let mut expected = x.clone();
                    expected.pow(quotient);
                    assert_ne!(expected, x.identity(), "regression must use a nontrivial proof");
                    let proof = generate_proof(&x, challenge, iterations, size_bits, k, l, &powers);
                    assert!(
                        verify_proof(challenge, x.clone(), y, proof.clone(), iterations, size_bits).is_ok(),
                        "invalid generated proof: L={}, k={}, T={}, challenge={:?}", l, k, iterations, challenge
                    );
                    assert_eq!(proof, expected, "wrong quotient exponent: L={l}, k={k}, T={iterations}, challenge={challenge:?}");
                    let encoded = serialize(&[proof.clone()], y, size_bits as usize);
                    assert!(WesolowskiVDFParams(size_bits).new().verify(challenge, iterations, &encoded).is_ok());

                    let mut reports = Vec::new();
                    let mut observe = |event| reports.push(event);
                    let observed = generate_proof_with_progress(
                        &x, challenge, iterations, size_bits, k, l, &powers,
                        &mut ProgressReporter::new(Some(&mut observe)),
                    );
                    assert_eq!(observed, proof, "progress must not change the proof");
                    assert!(reports.iter().any(|event| event.phase == SolvePhase::ProofBlocks));
                }
            }
        }
    }

    #[test]
    fn forced_l_1_matches_exact_quotient_and_verifies() {
        check_forced_parameters(1, &[3, 4, 11, 13]);
    }

    #[test]
    fn forced_l_2_matches_exact_quotient_and_verifies() {
        check_forced_parameters(2, &[3, 4, 11]);
    }

    #[test]
    fn forced_l_10_matches_exact_quotient_and_verifies() {
        check_forced_parameters(10, &[3, 4, 10, 11, 12]);
    }

    #[test]
    fn memory_parameter_boundary_keeps_production_policy() {
        for &(iterations, expected_l, expected_k) in super::large_difficulty_tests::CASES {
            let (l, k, _) = approximate_parameters(iterations as f64);
            assert_eq!((l, k), (expected_l, expected_k), "T={iterations}");
        }
    }

    // Smoke test: generate_proof + verify_proof agree when the same discriminant
    // is used — exercises the x.discriminant().to_bytes() path in both functions.
    #[test]
    fn generate_and_verify_agree_at_low_level() {
        let challenge = b"\xaa";
        let size_bits = 512u16;
        let iterations = 10u64;
        let x = generator(challenge, size_bits);
        let powers = powers_for(x.clone(), iterations);
        let (l, k, _) = approximate_parameters(iterations as f64);
        let proof = generate_proof(&x, challenge, iterations, size_bits, k, l, &powers);
        let y = powers[&iterations].clone();
        assert!(verify_proof(challenge, x, &y, proof, iterations, size_bits).is_ok());
    }

    // The Fiat-Shamir transcript now includes the discriminant bytes, so a proof
    // generated with one discriminant must not verify under a different one.
    // GmpClassGroup asserts discriminant equality on group operations in debug
    // builds, so both panic and Err are valid rejection signals here.
    #[test]
    fn wrong_discriminant_rejected_by_transcript() {
        let size_bits = 512u16;
        let iterations = 10u64;
        let x1 = generator(b"\xaa", size_bits);
        let x2 = generator(b"\xbb", size_bits);
        assert_ne!(
            x1.discriminant().to_bytes(),
            x2.discriminant().to_bytes(),
            "test requires two distinct discriminants"
        );
        let powers = powers_for(x1.clone(), iterations);
        let (l, k, _) = approximate_parameters(iterations as f64);
        let proof = generate_proof(&x1, b"\xaa", iterations, size_bits, k, l, &powers);
        let y = powers[&iterations].clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_proof(b"\xaa", x2, &y, proof, iterations, size_bits)
        }));
        assert!(matches!(result, Ok(Err(_)) | Err(_)));
    }

    // Sanity check that different challenges produce distinguishable discriminants
    // so the transcript entries actually differ.
    #[test]
    fn discriminant_bytes_differ_across_groups() {
        let d1: Num = super::super::create_discriminant::create_discriminant(b"\xaa", 512u16);
        let d2: Num = super::super::create_discriminant::create_discriminant(b"\xbb", 512u16);
        use classgroup::BigNum;
        assert_ne!(d1.to_bytes(), d2.to_bytes());
    }
}
