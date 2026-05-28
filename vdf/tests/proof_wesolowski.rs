// Copyright 2026 Trac Systems.
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

use vdf::{WesolowskiVDFParams, VDFParams, VDF};

fn vdf() -> vdf::WesolowskiVDF {
    WesolowskiVDFParams(2048).new()
}

// Wesolowski proof for challenge=b"\xaa", iterations=100, int_size_bits=2048.
// 516 bytes: first 258 = y (VDF output), last 258 = proof element.
// Generated with Baillie-PSW primality (num-bigint-dig) and Fiat-Shamir
// discriminant binding. ITERATIONS=200 ensures a non-trivial proof element
// (100 iterations produces the identity, which is transcript-independent).
const CHALLENGE: &[u8] = b"\xaa";
const ITERATIONS: u64 = 200;
#[rustfmt::skip]
const KNOWN_PROOF: &[u8] = &[
    // y (258 bytes)
    0,27,56,58,56,215,48,199,244,165,179,79,42,69,10,244,73,154,249,42,44,
    52,196,28,136,67,201,78,18,47,204,146,209,66,124,196,238,98,97,69,139,72,
    188,156,18,47,88,136,120,177,159,218,63,70,172,86,145,112,78,135,101,72,33,
    4,81,107,82,63,127,123,205,224,171,149,217,37,203,170,42,67,9,198,40,225,
    39,217,240,177,75,192,125,187,127,198,114,23,102,171,13,61,212,231,107,189,31,
    150,183,65,162,15,108,39,80,230,243,246,28,204,215,109,255,104,19,121,181,33,
    52,235,144,0,22,100,72,4,139,182,129,247,129,102,233,115,137,194,88,139,159,
    207,230,9,228,206,46,141,196,201,149,233,206,183,94,95,3,252,6,8,167,12,
    191,191,59,162,218,109,33,52,25,204,14,195,10,242,45,100,246,146,152,23,91,
    159,46,188,164,211,128,230,43,150,200,47,158,190,199,190,112,227,58,131,90,139,
    116,150,43,253,148,231,67,243,118,222,206,115,142,130,122,76,55,129,137,240,122,
    5,100,84,190,49,31,141,211,42,195,87,128,206,82,235,31,195,243,109,150,41,
    161,139,71,170,23,219,
    // proof element (258 bytes)
    0,59,192,70,33,174,50,1,31,4,97,34,61,202,52,45,83,90,22,22,160,
    92,231,178,9,168,224,52,171,53,150,168,129,15,195,114,239,107,120,133,190,153,
    63,76,113,169,192,199,46,212,87,245,165,191,83,113,75,127,35,189,245,59,164,
    214,250,184,168,207,151,3,160,140,167,107,174,19,55,195,105,9,200,13,2,118,
    52,244,53,134,237,172,246,29,133,172,123,64,213,250,20,209,139,205,188,29,48,
    250,204,51,38,93,192,208,183,238,212,81,190,88,125,9,203,189,213,91,45,239,
    52,28,188,0,20,35,172,158,14,224,40,35,86,186,79,50,85,147,169,56,201,
    253,11,16,234,4,113,17,79,217,255,45,194,192,54,40,251,219,187,210,5,22,
    120,186,174,64,195,142,83,165,34,244,105,151,220,76,197,242,203,21,66,119,170,
    12,198,96,12,246,43,150,238,244,117,212,172,245,156,198,11,155,110,7,221,184,
    41,220,27,240,63,8,89,18,94,204,181,209,91,185,15,252,114,2,88,20,53,
    137,88,47,218,190,85,104,10,94,57,32,124,79,98,17,12,77,63,242,96,196,
    103,154,133,184,233,213,
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
    let fast_vdf = WesolowskiVDFParams(512).new();
    for challenge in &[b"aa" as &[u8], b"deadbeef", b"trac", b"\x00\x01\x02"] {
        let proof = fast_vdf.solve(challenge, 50).unwrap();
        assert!(fast_vdf.verify(challenge, 50, &proof).is_ok());
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

#[test]
fn wrong_discriminant_size_fails_verification() {
    let small = WesolowskiVDFParams(512).new();
    let proof = small.solve(CHALLENGE, ITERATIONS).unwrap();
    assert!(vdf().verify(CHALLENGE, ITERATIONS, &proof).is_err());
}
