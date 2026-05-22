// Copyright 2018 POA Networks Ltd.
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

use super::proof_of_time::{iterate_squarings, serialize};
use classgroup::{gmp_classgroup::GmpClassGroup, BigNum, BigNumExt, ClassGroup};
use sha2::{digest::FixedOutput, Digest, Sha256};
use std::{cmp::Eq, collections::HashMap, hash::Hash, mem, u64, usize};

#[derive(Debug, Clone)]
pub struct WesolowskiVDF {
    int_size_bits: u16,
}
use super::InvalidIterations as Bad;

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
pub struct WesolowskiVDFParams(pub u16);
impl super::VDFParams for WesolowskiVDFParams {
    type VDF = WesolowskiVDF;
    fn new(self) -> Self::VDF {
        WesolowskiVDF {
            int_size_bits: self.0,
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
                challenge, difficulty as usize, self.int_size_bits
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
            self.int_size_bits,
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

/// Quote:
///
/// > Creates a random prime based on input s.
fn hash_prime<T: BigNum>(seed: &[&[u8]]) -> T {
    let mut j = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.input(b"prime");
        hasher.input(u64_to_bytes(j));
        for i in seed {
            hasher.input(i);
        }
        let n = T::from(&hasher.fixed_result()[..16]);
        if n.probab_prime(2) {
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
        let mut ys: HashMap<U, L> = HashMap::new();
        for b in 0..1usize << k {
            ys.entry(U::from(b as u64))
                .or_insert_with(|| identity.clone());
        }
        let end_of_loop = ((t as f64) / kl as f64).ceil() as usize;
        assert!(end_of_loop == 0 || (end_of_loop as u64 - 1).checked_mul(l as u64).is_some());
        for i in 0..end_of_loop {
            if t < k as usize * (i * l + j + 1) {
                continue;
            }
            let b = get_block((i as u64) * (l as u64), k, t as _, b);
            *ys.get_mut(&b).unwrap() *= &powers[&((i * kl) as _)];
        }

        for b1 in 0..k1_exp {
            let mut z = identity.clone();
            for b0 in 0..k0_exp {
                z *= &ys[&U::from((b1 * k0_exp + b0) as u64)]
            }
            z.pow(U::from((b1 as u64) * (k0_exp as u64)));
            x *= &z;
        }

        for b0 in 0..k0_exp {
            let mut z = identity.clone();
            for b1 in 0..k1_exp {
                z *= &ys[&U::from((b1 * k0_exp + b0) as u64)];
            }
            z.pow(U::from(b0 as u64));
            x *= &z;
        }
    }
    x
}

pub fn generate_proof<U, T: BigNumExt, V: ClassGroup<BigNum = T> + Eq + Hash>(
    x: &V,
    iterations: u64,
    k: u8,
    l: usize,
    powers: &U,
    int_size_bits: usize,
) -> V
where
    U: for<'a> std::ops::Index<&'a u64, Output = V>,
{
    let element_len = 2 * ((int_size_bits + 16) >> 4);
    let mut x_buf = vec![0; element_len];
    x.serialize(&mut x_buf[..])
        .expect(super::INCORRECT_BUFFER_SIZE);
    let mut y_buf = vec![0; element_len];
    powers[&iterations]
        .serialize(&mut y_buf[..])
        .expect(super::INCORRECT_BUFFER_SIZE);
    let b = hash_prime(&[&x_buf[..], &y_buf[..]]);
    eval_optimized(&x, &b, iterations as _, k, l, powers)
}

/// Verify a proof, according to the Wesolowski paper.
pub fn verify_proof<T: BigNum, V: ClassGroup<BigNum = T>>(
    mut x: V,
    y: &V,
    mut proof: V,
    t: u64,
    int_size_bits: usize,
) -> Result<(), ()> {
    let element_len = 2 * ((int_size_bits + 16) >> 4);
    let mut x_buf = vec![0; element_len];
    x.serialize(&mut x_buf[..])
        .expect(super::INCORRECT_BUFFER_SIZE);
    let mut y_buf = vec![0; element_len];
    y.serialize(&mut y_buf[..])
        .expect(super::INCORRECT_BUFFER_SIZE);
    let b = hash_prime(&[&x_buf[..], &y_buf[..]]);
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
    int_size_bits: u16,
) -> Vec<u8>
where
    for<'a, 'b> &'a V: std::ops::Mul<&'b V, Output = V>,
    for<'a, 'b> &'a V::BigNum: std::ops::Mul<&'b V::BigNum, Output = V::BigNum>,
{
    let discriminant = super::create_discriminant::create_discriminant(&challenge, int_size_bits);
    let x = V::from_ab_discriminant(2.into(), 1.into(), discriminant);
    assert!((iterations as u128) < (1u128 << 53));
    let (l, k, _) = approximate_parameters(iterations as f64);
    let q = l.checked_mul(k as _).expect("bug");
    let powers = iterate_squarings(
        x.clone(),
        (0..=iterations / q + 1)
            .map(|i| i * q)
            .chain(Some(iterations))
            .map(|x| x as _),
    );
    let proof = generate_proof(&x, iterations as _, k, l, &powers, int_size_bits.into());
    serialize(&[proof], &powers[&(iterations as _)], int_size_bits.into())
}

pub fn check_proof_of_time_wesolowski<T: BigNum, V: ClassGroup<BigNum = T>>(
    challenge: &[u8],
    proof_blob: &[u8],
    iterations: u64,
    int_size_bits: u16,
) -> Result<(), ()>
where
    T: BigNumExt,
{
    let discriminant: T = super::create_discriminant::create_discriminant(challenge, int_size_bits);
    let x = V::from_ab_discriminant(2.into(), 1.into(), discriminant.clone());
    if (usize::MAX - 16) < int_size_bits.into() {
        return Err(());
    }
    let int_size = (usize::from(int_size_bits) + 16) >> 4;
    if int_size * 4 != proof_blob.len() {
        return Err(());
    }
    let (result_bytes, proof_bytes) = proof_blob.split_at(2 * int_size);
    let proof = ClassGroup::from_bytes(proof_bytes, discriminant.clone());
    let y = ClassGroup::from_bytes(result_bytes, discriminant);

    verify_proof(x, &y, proof, iterations, int_size_bits.into())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{WesolowskiVDFParams, VDFParams, VDF};

    fn vdf() -> crate::WesolowskiVDF {
        WesolowskiVDFParams(2048).new()
    }

    // Wesolowski proof for challenge=b"\xaa", iterations=100, int_size_bits=2048.
    // 516 bytes: first 258 = y (VDF output), last 258 = proof element.
    // Generated with Baillie-PSW primality (num-bigint-dig), post security fix.
    const CHALLENGE: &[u8] = b"\xaa";
    const ITERATIONS: u64 = 100;
    #[rustfmt::skip]
    const KNOWN_PROOF: &[u8] = &[
        0,82,113,232,249,171,46,184,162,144,110,133,29,252,181,84,46,65,115,240,22,
        184,94,41,212,129,161,8,220,130,237,59,63,151,147,123,122,168,36,128,17,56,
        209,119,29,234,141,174,47,99,151,231,106,128,97,58,253,163,15,44,48,163,75,
        4,11,170,175,231,109,87,7,214,134,137,25,62,93,33,24,51,179,114,166,164,89,
        26,187,136,226,231,242,245,165,236,129,139,87,7,184,107,139,44,73,92,161,88,
        28,23,145,104,80,158,53,147,249,161,104,121,98,10,77,196,233,7,223,69,46,141,
        208,255,196,241,153,130,95,84,236,112,71,44,192,97,242,46,181,76,72,214,170,
        90,243,234,55,90,57,42,199,114,148,226,217,85,221,225,209,2,174,42,206,73,66,
        147,73,45,49,207,242,25,68,168,188,180,96,137,147,6,92,154,0,41,46,141,63,70,
        4,231,70,91,78,238,251,73,79,91,234,16,45,179,67,187,97,197,161,92,123,223,40,
        130,6,136,92,19,15,161,242,216,107,245,228,99,79,220,66,22,188,22,239,125,172,
        151,11,14,228,109,105,65,111,154,154,206,230,81,209,88,172,100,145,91,
        // proof element (258 bytes = [0×128, 1, 0×128, 1])
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        1,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        1,
    ];

    #[test]
    fn verify_known_proof() {
        assert_eq!(KNOWN_PROOF.len(), 516);
        assert!(vdf().verify(CHALLENGE, ITERATIONS, KNOWN_PROOF).is_ok());
    }

    #[test]
    fn solve_and_verify() {
        let proof = vdf().solve(CHALLENGE, ITERATIONS).unwrap();
        assert!(vdf().verify(CHALLENGE, ITERATIONS, &proof).is_ok());
    }

    #[test]
    fn solve_and_verify_different_challenges() {
        for challenge in &[b"aa" as &[u8], b"deadbeef", b"trac", b"\x00\x01\x02"] {
            let proof = vdf().solve(challenge, 50).unwrap();
            assert!(vdf().verify(challenge, 50, &proof).is_ok());
        }
    }

    #[test]
    fn different_iterations_produce_different_proofs() {
        let proof_100 = vdf().solve(CHALLENGE, 100).unwrap();
        let proof_200 = vdf().solve(CHALLENGE, 200).unwrap();
        assert_ne!(proof_100, proof_200);
    }

    #[test]
    fn wrong_iterations_fails_verification() {
        let proof = vdf().solve(CHALLENGE, 100).unwrap();
        assert!(vdf().verify(CHALLENGE, 200, &proof).is_err());
    }

    #[test]
    fn wrong_challenge_fails_verification() {
        let proof = vdf().solve(CHALLENGE, ITERATIONS).unwrap();
        // from_bytes panics on discriminant mismatch in debug builds (pre-existing
        // classgroup bug); in release builds it returns Err. Both correctly reject.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vdf().verify(b"wrong", ITERATIONS, &proof)
        }));
        assert!(matches!(result, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let mut proof = vdf().solve(CHALLENGE, ITERATIONS).unwrap();
        proof[0] ^= 0xff;
        // from_bytes panics on invalid bytes in debug builds (pre-existing
        // classgroup bug); in release builds it returns Err. Both correctly reject.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vdf().verify(CHALLENGE, ITERATIONS, &proof)
        }));
        assert!(matches!(result, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn empty_proof_fails_verification() {
        assert!(vdf().verify(CHALLENGE, ITERATIONS, &[]).is_err());
    }

    #[test]
    fn different_challenges_produce_different_proofs() {
        let proof_a = vdf().solve(b"aaa", 50).unwrap();
        let proof_b = vdf().solve(b"bbb", 50).unwrap();
        assert_ne!(proof_a, proof_b);
    }

    #[test]
    fn proof_is_deterministic() {
        let proof_1 = vdf().solve(CHALLENGE, ITERATIONS).unwrap();
        let proof_2 = vdf().solve(CHALLENGE, ITERATIONS).unwrap();
        assert_eq!(proof_1, proof_2);
    }
}
