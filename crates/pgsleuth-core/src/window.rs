// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! Windowing helpers used by stateful rules.
//!
//! Design 001 § D4 calls out two evaluator window kinds shipped with
//! `pgsleuth-core`: `consecutive_intervals` and `rolling_histogram`.
//! This module implements the first; rolling histograms land with the
//! polling rules.
//!
//! Pulled out of any specific rule's evaluator so the v0 fsync-jitter
//! skeleton (#43) can use it inline before the full rule engine lands.

/// Counts consecutive evaluation intervals in which some computed
/// metric breached a threshold. Resets to zero on a non-breach, so it
/// is the right shape for "fires after N consecutive intervals over
/// X" rules — e.g. Alarm 03 (fsync jitter): commit latency > 10ms for
/// > 3 consecutive 1-second intervals.
///
/// The counter does NOT itself compare values to a threshold — the
/// caller does. The counter just tracks the run of "yes" calls.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConsecutiveBreachCounter {
    streak: u32,
    /// True once the streak has reached `fire_after` for the first
    /// time in this run, and reset to false when the streak breaks.
    /// Lets a caller distinguish "first fire" from "still firing".
    fired_this_run: bool,
}

/// Outcome of feeding the counter one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachState {
    /// Streak still running; below `fire_after`.
    Building {
        /// Number of consecutive breaching intervals observed so far.
        streak: u32,
    },
    /// Streak just reached `fire_after` for the first time. The
    /// caller should emit a finding *now*.
    JustFired {
        /// Number of consecutive breaching intervals observed so far.
        streak: u32,
    },
    /// Streak is at or past `fire_after` but the alarm is already
    /// known firing. Caller typically suppresses duplicate findings.
    StillFiring {
        /// Number of consecutive breaching intervals observed so far.
        streak: u32,
    },
    /// Latest interval was a non-breach. Streak is reset.
    Reset,
}

impl ConsecutiveBreachCounter {
    /// Feed one interval's result. `breached` is `true` when this
    /// interval's value violated the rule's threshold. `fire_after`
    /// is the rule's "for N consecutive intervals" parameter.
    pub fn observe(&mut self, breached: bool, fire_after: u32) -> BreachState {
        if !breached {
            self.streak = 0;
            self.fired_this_run = false;
            return BreachState::Reset;
        }
        self.streak = self.streak.saturating_add(1);
        if self.streak < fire_after {
            return BreachState::Building {
                streak: self.streak,
            };
        }
        if self.fired_this_run {
            BreachState::StillFiring {
                streak: self.streak,
            }
        } else {
            self.fired_this_run = true;
            BreachState::JustFired {
                streak: self.streak,
            }
        }
    }

    /// Current streak length. Useful for evidence on the finding.
    #[must_use]
    pub fn streak(&self) -> u32 {
        self.streak
    }

    /// Whether the alarm is currently in the firing state.
    #[must_use]
    pub fn is_firing(&self) -> bool {
        self.fired_this_run
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_after_n_consecutive_breaches() {
        let mut c = ConsecutiveBreachCounter::default();
        assert_eq!(c.observe(true, 3), BreachState::Building { streak: 1 });
        assert_eq!(c.observe(true, 3), BreachState::Building { streak: 2 });
        assert_eq!(c.observe(true, 3), BreachState::JustFired { streak: 3 });
        assert!(c.is_firing());
        assert_eq!(c.observe(true, 3), BreachState::StillFiring { streak: 4 });
    }

    #[test]
    fn reset_on_non_breach() {
        let mut c = ConsecutiveBreachCounter::default();
        c.observe(true, 3);
        c.observe(true, 3);
        assert_eq!(c.observe(false, 3), BreachState::Reset);
        assert_eq!(c.observe(true, 3), BreachState::Building { streak: 1 });
        assert!(!c.is_firing());
    }

    #[test]
    fn rearming_after_recovery_can_refire() {
        let mut c = ConsecutiveBreachCounter::default();
        c.observe(true, 2);
        assert_eq!(c.observe(true, 2), BreachState::JustFired { streak: 2 });
        c.observe(false, 2);
        // After recovery, the next sustained breach is a fresh fire.
        c.observe(true, 2);
        assert_eq!(c.observe(true, 2), BreachState::JustFired { streak: 2 });
    }

    #[test]
    fn fire_after_one_fires_immediately() {
        let mut c = ConsecutiveBreachCounter::default();
        assert_eq!(c.observe(true, 1), BreachState::JustFired { streak: 1 });
        assert_eq!(c.observe(true, 1), BreachState::StillFiring { streak: 2 });
    }
}
