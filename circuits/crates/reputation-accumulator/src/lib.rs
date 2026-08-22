//! reputation-accumulator
//!
//! Implements the aggregation rule from docs/PROTOCOL_SPEC.md §5:
//! confidence(X, E) = sum of tier_weight(N_i) over valid, distinct-nullifier
//! proofs for indicator X in epoch E.
//!
//! This crate assumes proofs have *already* been cryptographically verified
//! (by the relay, using `proof-of-observation`) before reaching `accumulate`.
//! It is only responsible for: (a) rejecting replayed nullifiers, per
//! docs/PROTOCOL_SPEC.md §4, and (b) folding tier-weighted counts into a
//! per-(indicator, epoch) score, per §5.
//!
//! Deliberately a pure function over an in-memory batch, with no I/O and no
//! persistence — the relay owns storage/persistence decisions. This keeps
//! the scoring rule itself trivially testable and auditable in isolation.

use std::collections::{HashMap, HashSet};

/// A weighting policy: how many points a proof at a given tier contributes.
/// Not hardcoded as a single global constant on purpose — different
/// consumer communities may reasonably want different weighting, and the
/// Sybil-resistance caveat in docs/THREAT_MODEL.md means tier-0 weight in
/// particular should stay tunable rather than fixed by this crate.
#[derive(Debug, Clone)]
pub struct TierWeights {
    weights: [u32; 4],
}

impl TierWeights {
    /// Placeholder default: 1 / 2 / 4 / 8 for tiers 0-3. Revisit once
    /// real-world Sybil pressure on tier-0 is understood (see
    /// docs/THREAT_MODEL.md).
    pub fn default_weights() -> Self {
        Self {
            weights: [1, 2, 4, 8],
        }
    }

    pub fn new(weights: [u32; 4]) -> Self {
        Self { weights }
    }

    /// Returns 0 for any tier outside 0-3 rather than panicking — an
    /// out-of-range tier should never reach this crate if the relay's
    /// proof verification is correct, but scoring code shouldn't be the
    /// thing that panics on malformed input.
    pub fn weight_for(&self, tier: u8) -> u32 {
        self.weights.get(tier as usize).copied().unwrap_or(0)
    }
}

impl Default for TierWeights {
    fn default() -> Self {
        Self::default_weights()
    }
}

/// A verified (cryptographically checked) observation proof, ready for
/// aggregation. Constructing one of these should only happen after the
/// relay has verified the underlying Groth16 proof — this type carries no
/// proof material itself, only the claims the proof attested to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifiedObservation {
    pub indicator_hash: String,
    pub epoch: u64,
    pub nullifier: String,
    pub tier: u8,
}

/// Result of accumulating a batch: the score table plus which observations
/// were dropped as replays, so the relay can log/alert on replay attempts
/// rather than have them silently vanish.
#[derive(Debug, Default)]
pub struct AccumulationResult {
    pub scores: HashMap<(String, u64), u32>,
    pub rejected_replays: Vec<VerifiedObservation>,
}

/// Fold a batch of verified observations into per-(indicator, epoch) scores.
///
/// Order-independent except for replay detection, which is applied in
/// input order: if the same nullifier appears twice in one batch, only the
/// first occurrence counts and the rest are reported in `rejected_replays`.
/// A `seen_nullifiers` set is threaded in from the caller so replay
/// detection also works *across* batches (e.g. across relay restarts, if
/// the caller persists and reloads the set) — this crate does not own
/// nullifier persistence.
pub fn accumulate(
    observations: &[VerifiedObservation],
    seen_nullifiers: &mut HashSet<String>,
    weights: &TierWeights,
) -> AccumulationResult {
    let mut result = AccumulationResult::default();

    for obs in observations {
        if seen_nullifiers.contains(&obs.nullifier) {
            result.rejected_replays.push(obs.clone());
            continue;
        }
        seen_nullifiers.insert(obs.nullifier.clone());

        let key = (obs.indicator_hash.clone(), obs.epoch);
        let weight = weights.weight_for(obs.tier);
        *result.scores.entry(key).or_insert(0) += weight;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(indicator: &str, epoch: u64, nullifier: &str, tier: u8) -> VerifiedObservation {
        VerifiedObservation {
            indicator_hash: indicator.to_string(),
            epoch,
            nullifier: nullifier.to_string(),
            tier,
        }
    }

    #[test]
    fn single_observation_scores_by_tier_weight() {
        let mut seen = HashSet::new();
        let weights = TierWeights::default_weights();
        let batch = vec![obs("abc123", 1, "null-1", 2)];

        let result = accumulate(&batch, &mut seen, &weights);

        assert_eq!(result.scores.get(&("abc123".to_string(), 1)), Some(&4));
        assert!(result.rejected_replays.is_empty());
    }

    #[test]
    fn multiple_distinct_contributors_sum_weights() {
        let mut seen = HashSet::new();
        let weights = TierWeights::default_weights();
        let batch = vec![
            obs("abc123", 1, "null-1", 0), // weight 1
            obs("abc123", 1, "null-2", 3), // weight 8
            obs("abc123", 1, "null-3", 1), // weight 2
        ];

        let result = accumulate(&batch, &mut seen, &weights);

        assert_eq!(result.scores.get(&("abc123".to_string(), 1)), Some(&11));
    }

    #[test]
    fn replayed_nullifier_within_batch_is_rejected_not_double_counted() {
        let mut seen = HashSet::new();
        let weights = TierWeights::default_weights();
        let batch = vec![
            obs("abc123", 1, "null-1", 3),
            obs("abc123", 1, "null-1", 3), // same nullifier, replay
        ];

        let result = accumulate(&batch, &mut seen, &weights);

        assert_eq!(result.scores.get(&("abc123".to_string(), 1)), Some(&8));
        assert_eq!(result.rejected_replays.len(), 1);
        assert_eq!(result.rejected_replays[0].nullifier, "null-1");
    }

    #[test]
    fn replay_detection_persists_across_calls_via_shared_seen_set() {
        let mut seen = HashSet::new();
        let weights = TierWeights::default_weights();

        let first_batch = vec![obs("abc123", 1, "null-1", 2)];
        let first = accumulate(&first_batch, &mut seen, &weights);
        assert_eq!(first.scores.get(&("abc123".to_string(), 1)), Some(&4));

        // Second "batch" (e.g. after a relay restart that reloaded `seen`
        // from persistence) replays the same nullifier for the same
        // indicator/epoch and must be rejected, not re-scored.
        let second_batch = vec![obs("abc123", 1, "null-1", 2)];
        let second = accumulate(&second_batch, &mut seen, &weights);
        assert!(second.scores.is_empty());
        assert_eq!(second.rejected_replays.len(), 1);
    }

    #[test]
    fn different_epochs_are_scored_independently() {
        let mut seen = HashSet::new();
        let weights = TierWeights::default_weights();
        let batch = vec![
            obs("abc123", 1, "null-1", 2),
            obs("abc123", 2, "null-2", 2), // same indicator, different epoch
        ];

        let result = accumulate(&batch, &mut seen, &weights);

        assert_eq!(result.scores.get(&("abc123".to_string(), 1)), Some(&4));
        assert_eq!(result.scores.get(&("abc123".to_string(), 2)), Some(&4));
    }

    #[test]
    fn out_of_range_tier_contributes_zero_weight_rather_than_panicking() {
        let mut seen = HashSet::new();
        let weights = TierWeights::default_weights();
        let batch = vec![obs("abc123", 1, "null-1", 99)];

        let result = accumulate(&batch, &mut seen, &weights);

        assert_eq!(result.scores.get(&("abc123".to_string(), 1)), Some(&0));
    }

    #[test]
    fn custom_weights_are_respected() {
        let mut seen = HashSet::new();
        let weights = TierWeights::new([0, 1, 1, 100]);
        let batch = vec![obs("abc123", 1, "null-1", 3)];

        let result = accumulate(&batch, &mut seen, &weights);

        assert_eq!(result.scores.get(&("abc123".to_string(), 1)), Some(&100));
    }
}
