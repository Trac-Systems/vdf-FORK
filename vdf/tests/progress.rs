use std::collections::HashMap;
use vdf::{SolvePhase, VDFParams, WesolowskiVDFParams, VDF};

#[test]
fn observations_preserve_proof_bytes_and_report_completed_work() {
    for bits in [40, 512, 1024, 2048] {
        let solver = WesolowskiVDFParams(bits).new();
        let expected = solver.solve(b"progress compatibility", 513).unwrap();
        let mut events = Vec::new();
        let actual = solver
            .solve_with_progress(b"progress compatibility", 513, &mut |p| events.push(p))
            .unwrap();
        assert_eq!(actual, expected);
        assert!(solver
            .verify(b"progress compatibility", 513, &actual)
            .is_ok());
        let mut counts = HashMap::new();
        for event in &events {
            let previous = counts
                .insert(event.phase as u32, event.completed)
                .unwrap_or(0);
            assert!(event.completed > previous);
        }
        for phase in [
            SolvePhase::DiscriminantSieve,
            SolvePhase::DiscriminantCandidates,
            SolvePhase::Squaring,
            SolvePhase::ChallengePrime,
            SolvePhase::ProofSetup,
            SolvePhase::ProofBlocks,
            SolvePhase::ProofAggregation,
            SolvePhase::Serialization,
        ] {
            assert!(
                counts.contains_key(&(phase as u32)),
                "missing phase: {:?}",
                phase
            );
        }
        assert!(counts[&(SolvePhase::Squaring as u32)] >= 513);
        assert_eq!(events.last().unwrap().phase, SolvePhase::Serialization);
    }
}

#[test]
fn a_new_solve_has_independent_counters() {
    let solver = WesolowskiVDFParams(512).new();
    let mut first = Vec::new();
    let mut second = Vec::new();
    solver
        .solve_with_progress(b"repeat", 128, &mut |p| first.push(p))
        .unwrap();
    solver
        .solve_with_progress(b"repeat", 128, &mut |p| second.push(p))
        .unwrap();
    assert_eq!(first, second);
}
