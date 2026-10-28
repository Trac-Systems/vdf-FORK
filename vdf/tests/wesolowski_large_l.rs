// Copyright 2026 Trac Systems.
// Licensed under the Apache License, Version 2.0.

use std::time::Instant;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

const ITERATIONS: u64 = 12_000_000;

fn challenge() -> Vec<u8> {
    hex::decode(include_str!("fixtures/lab_12000000_1024.challenge.hex").trim()).unwrap()
}

fn invalid_proof() -> Vec<u8> {
    hex::decode(include_str!("fixtures/lab_12000000_1024.invalid-proof.hex").trim()).unwrap()
}

#[test]
fn captured_invalid_large_l_proof_is_rejected() {
    let proof = invalid_proof();
    assert_eq!(proof.len(), 260);
    assert!(WesolowskiVDFParams(1024).new().verify(&challenge(), ITERATIONS, &proof).is_err());
}

// Verification of real high-difficulty proofs is cheap enough for ordinary CI.
// Regenerate explicitly with checkpoints_10m_to_50m_1024; never during this test.
#[test]
fn saved_proofs_10m_to_50m_verify_only_at_the_correct_difficulty() {
    let expected = [
        10_000_000, 10_000_001, 12_000_000, 20_000_000,
        30_000_000, 31_000_000, 40_000_000, 50_000_000,
    ];
    let mut actual = Vec::new();
    let challenge = challenge();
    let solver = WesolowskiVDFParams(1024).new();
    for line in include_str!("fixtures/wesolowski_10m_50m.csv").lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 3);
        let iterations: u64 = fields[0].parse().unwrap();
        assert_eq!(fields[1], "1024");
        let proof = hex::decode(fields[2]).unwrap();
        assert_eq!(proof.len(), 260);
        assert!(solver.verify(&challenge, iterations, &proof).is_ok(), "T={}", iterations);
        assert!(solver.verify(&challenge, iterations + 1, &proof).is_err(), "wrong T={}", iterations);
        actual.push(iterations);
    }
    assert_eq!(actual, expected, "all eight checkpoints must be present in order");
}

fn solve_and_verify(bits: u16) {
    let solver = WesolowskiVDFParams(bits).new();
    let challenge = challenge();
    let started = Instant::now();
    let proof = solver.solve(&challenge, ITERATIONS).unwrap();
    eprintln!("T={ITERATIONS}, bits={bits}: solve took {:?}", started.elapsed());
    assert_eq!(proof.len(), 4 * ((bits as usize + 16) >> 4));
    assert!(solver.verify(&challenge, ITERATIONS, &proof).is_ok());
    if bits == 1024 {
        let old = invalid_proof();
        assert_ne!(proof, old, "generate a new proof, do not accept the broken one");
        assert_eq!(&proof[..130], &old[..130], "VDF output y must remain unchanged");
        assert!(solver.verify(&challenge, ITERATIONS, &old).is_err());
    }
    // Optional output for cross-runtime verification; ordinary tests write nothing.
    if let Some(path) = std::env::var_os("VDF_LARGE_L_PROOF_OUTPUT") {
        std::fs::write(path, hex::encode(&proof)).unwrap();
    }
    eprintln!("T={ITERATIONS}, bits={bits}: fresh proof verified");
}

#[test]
#[ignore = "12 million squarings; run explicitly in release mode"]
fn solve_verify_12000000_1024() {
    solve_and_verify(1024);
}

#[test]
#[ignore = "12 million squarings at 2048 bits; run explicitly in release mode"]
fn solve_verify_12000000_2048() {
    solve_and_verify(2048);
}
