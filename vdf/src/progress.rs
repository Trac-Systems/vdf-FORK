//! Observations of completed work during a solve. These do not affect the proof.

/// The operation whose completed work is being reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SolvePhase {
    /// Prime sieve entries processed while generating the discriminant.
    DiscriminantSieve = 1,
    /// Discriminant candidates tested for primality.
    DiscriminantCandidates = 2,
    /// Sequential class-group squarings completed.
    Squaring = 3,
    /// Fiat-Shamir prime candidates tested.
    ChallengePrime = 4,
    /// Proof accumulator entries initialized.
    ProofSetup = 5,
    /// Proof blocks evaluated and accumulated.
    ProofBlocks = 6,
    /// Class-group operations completed while combining proof accumulators.
    ProofAggregation = 7,
    /// Proof serialization completed.
    Serialization = 8,
}

/// A cumulative count for one phase of a single solve, not a percentage or a timer heartbeat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolveProgress {
    /// The kind of work completed.
    pub phase: SolvePhase,
    /// Completed operations in this phase, including earlier visits to the phase.
    pub completed: u64,
}

pub(crate) const REPORT_EVERY: u64 = 128;

pub(crate) struct ProgressReporter<'a> {
    observer: Option<&'a mut dyn FnMut(SolveProgress)>,
    counts: [u64; 8],
    reported: [u64; 8],
    last_phase: Option<SolvePhase>,
}

impl<'a> ProgressReporter<'a> {
    pub(crate) fn new(observer: Option<&'a mut dyn FnMut(SolveProgress)>) -> Self {
        Self {
            observer,
            counts: [0; 8],
            reported: [0; 8],
            last_phase: None,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.observer.is_some()
    }

    pub(crate) fn advance(&mut self, phase: SolvePhase, amount: u64) {
        if !self.enabled() || amount == 0 {
            return;
        }
        let index = phase as usize - 1;
        self.counts[index] += amount;
        if self.last_phase != Some(phase)
            || self.counts[index] - self.reported[index] >= REPORT_EVERY
        {
            self.flush(phase);
        }
    }

    pub(crate) fn flush(&mut self, phase: SolvePhase) {
        let index = phase as usize - 1;
        if self.counts[index] == self.reported[index] {
            return;
        }
        if let Some(observer) = self.observer.as_mut() {
            observer(SolveProgress {
                phase,
                completed: self.counts[index],
            });
        }
        self.reported[index] = self.counts[index];
        self.last_phase = Some(phase);
    }
}
