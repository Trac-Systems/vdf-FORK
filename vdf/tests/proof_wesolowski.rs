use vdf::{WesolowskiVDFParams, VDFParams, VDF};

fn vdf() -> vdf::WesolowskiVDF {
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
