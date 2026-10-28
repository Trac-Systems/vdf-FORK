// Copyright 2026 Trac Systems.
// Licensed under the Apache License, Version 2.0.

use super::*;
use crate::{VDFParams, VDF};
use std::time::Instant;

// Include the L transition and both subsequent k values. These are expected
// production parameters, not overrides that lower the actual difficulty.
pub(super) const CASES: &[(u64, usize, u8)] = &[
    (10_000_000, 1, 13),
    (10_000_001, 10, 10),
    (12_000_000, 10, 11),
    (20_000_000, 10, 11),
    (30_000_000, 10, 11),
    (31_000_000, 10, 12),
    (40_000_000, 10, 12),
    (50_000_000, 10, 12),
];

// This is a real 1024-bit classgroup run to 50 million squarings. Reusing the
// same challenge's sequential prefix avoids 203 million independent squarings.
// Each checkpoint still gets its own Fiat-Shamir prime, proof and verification.
// It supplements the public solve() tests; it is not eight public solve() calls.
#[test]
#[ignore = "explicit release-only batch: 50 million squarings, eight proofs; allow minutes and ~1 GiB RAM"]
fn checkpoints_10m_to_50m_1024() {
    assert!(!cfg!(debug_assertions), "run this test with --release");
    type G = GmpClassGroup;
    type Num = <G as ClassGroup>::BigNum;
    let challenge = hex::decode(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lab_12000000_1024.challenge.hex"
    )).trim()).unwrap();
    let bits = 1024u16;
    let discriminant: Num = crate::create_discriminant(&challenge, bits);
    let x = G::from_ab_discriminant(2.into(), 1.into(), discriminant);
    let mut required = Vec::new();
    for &(iterations, expected_l, expected_k) in CASES {
        let (l, k, _) = approximate_parameters(iterations as f64);
        assert_eq!((l, k), (expected_l, expected_k));
        let stride = l as u64 * u64::from(k);
        // The evaluator only reads cached stride powers up to T, plus y at T.
        required.extend((0..=iterations / stride).map(|i| i * stride));
        required.push(iterations);
    }
    required.sort_unstable();
    required.dedup();
    eprintln!("Preparing {} cached powers for {} real proofs", required.len(), CASES.len());
    let started = Instant::now();
    let mut next_report = 5_000_000;
    let mut observe = |event: SolveProgress| {
        if event.phase == SolvePhase::Squaring && event.completed >= next_report {
            eprintln!("squaring {} / 50000000, elapsed {:?}", event.completed, started.elapsed());
            next_report += 5_000_000;
        }
    };
    let powers = crate::proof_of_time::iterate_squarings_with_progress(
        x.clone(), required.into_iter(), &mut ProgressReporter::new(Some(&mut observe)),
    );
    let solver = WesolowskiVDFParams(bits).new();
    let mut vectors = String::from("# difficulty,discriminant_bits,proof_hex; challenge is lab_12000000_1024.challenge.hex\n");
    for &(iterations, l, k) in CASES {
        let proof_started = Instant::now();
        let proof = generate_proof(&x, &challenge, iterations, bits, k, l, &powers);
        assert_ne!(proof, x.identity(), "T={iterations}: proof must be nontrivial");
        let y = &powers[&iterations];
        assert!(verify_proof(&challenge, x.clone(), y, proof.clone(), iterations, bits).is_ok());
        let encoded = serialize(&[proof], y, bits as usize);
        assert_eq!(encoded.len(), 260);
        assert!(solver.verify(&challenge, iterations, &encoded).is_ok());
        // A valid encoding with a different group proof must still be rejected.
        let mut incorrect = G::from_bytes(&encoded[130..], x.discriminant().clone());
        incorrect *= &x;
        let invalid = serialize(&[incorrect], y, bits as usize);
        assert!(solver.verify(&challenge, iterations, &invalid).is_err());
        vectors.push_str(&format!("{},{},{}\n", iterations, bits, hex::encode(&encoded)));
        eprintln!("T={iterations}, L={l}, k={k}: proof verified in {:?}; total {:?}", proof_started.elapsed(), started.elapsed());
    }
    // Explicit output only. The default test run never rewrites known vectors.
    if let Some(path) = std::env::var_os("VDF_LARGE_L_VECTORS_OUTPUT") {
        std::fs::write(path, vectors).unwrap();
    }
    eprintln!("All {} checkpoints verified in {:?}", CASES.len(), started.elapsed());
}
