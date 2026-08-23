//! umbra-relay library: HTTP surface + verification/scoring glue for the
//! reference relay described in docs/ARCHITECTURE.md.
//!
//! Split into a library (this crate) plus three thin binaries
//! (`src/bin/server.rs`, `keygen.rs`, `prove.rs`) so the request-handling
//! logic here is unit-testable without a real TCP listener, and so
//! `keygen`/`prove` can reuse it (e.g. `encoding`) without duplicating it.
//!
//! Phase 1 caveats that matter for anyone reading this as a spec: proofs
//! are only checked against whatever verifying key the relay was started
//! with (see `umbra-relay-keygen`'s warning banner — it's a local,
//! non-ceremony setup). The circuit now cryptographically enforces
//! `credential_tier >= min_tier` *relative to whichever credential tree
//! `credential_root` names* — but the circuit has no opinion on whether
//! that tree was honestly vetted by a real issuer. That's a policy
//! question this relay answers via `trusted_credential_roots`: a
//! submission's claimed `min_tier` is only trusted for scoring weight if
//! its `credential_root` is in that allowlist; otherwise (including the
//! Phase 0 default of an empty allowlist, since no real issuer exists
//! yet) every observation is scored as tier 0, regardless of what the
//! proof itself attests to. See `submit_observation` and
//! docs/THREAT_MODEL.md.

pub mod encoding;
pub mod state;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use reputation_accumulator::{accumulate, VerifiedObservation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use encoding::{fr_from_hex, fr_to_hex, proof_from_hex};
use state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/observations", post(submit_observation))
        .route("/v1/score/:indicator_hash/:epoch", get(get_score))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Debug, Deserialize)]
pub struct SubmitObservationRequest {
    /// Hex-encoded `Fr` — Poseidon(normalized_indicator).
    pub indicator_hash: String,
    pub epoch: u64,
    /// Hex-encoded `Fr` — the epoch's published Merkle root.
    pub root: String,
    /// Hex-encoded `Fr` — replay-protection nullifier.
    pub nullifier: String,
    /// Claimed tier (0-3). Cryptographically checked against
    /// `credential_root` as of the tier-gate gadget in
    /// proof-of-observation — a mismatched claim now fails proof
    /// verification, not just this relay's (former) trust-the-claim
    /// behavior. See module docs.
    pub min_tier: u8,
    /// Hex-encoded `Fr` — root of the issuer-published credential tree
    /// this proof's tier claim was checked against.
    pub credential_root: String,
    /// Hex-encoded, canonically-serialized Groth16 `Proof<Bn254>`.
    pub proof: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitObservationResponse {
    pub accepted: bool,
    pub reason: Option<String>,
    pub score: Option<u32>,
}

fn rejected(reason: &str) -> Json<SubmitObservationResponse> {
    Json(SubmitObservationResponse {
        accepted: false,
        reason: Some(reason.to_string()),
        score: None,
    })
}

async fn submit_observation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitObservationRequest>,
) -> Json<SubmitObservationResponse> {
    let indicator_hash = match fr_from_hex(&req.indicator_hash) {
        Ok(v) => v,
        Err(e) => return rejected(&e.to_string()),
    };
    let root = match fr_from_hex(&req.root) {
        Ok(v) => v,
        Err(e) => return rejected(&e.to_string()),
    };
    let nullifier = match fr_from_hex(&req.nullifier) {
        Ok(v) => v,
        Err(e) => return rejected(&e.to_string()),
    };
    let credential_root = match fr_from_hex(&req.credential_root) {
        Ok(v) => v,
        Err(e) => return rejected(&e.to_string()),
    };
    let proof: Proof<Bn254> = match proof_from_hex(&req.proof) {
        Ok(v) => v,
        Err(e) => return rejected(&e.to_string()),
    };

    // Field-element ordering here must match `PublicInputs`'s field order
    // in proof-of-observation's lib.rs (indicator_hash, epoch, root,
    // nullifier, min_tier, credential_root) — Groth16::verify has no way
    // to catch a silently-reordered public-input vector.
    let epoch_fr = Fr::from(req.epoch);
    let min_tier_fr = Fr::from(req.min_tier as u64);
    let public_inputs = vec![
        indicator_hash,
        epoch_fr,
        root,
        nullifier,
        min_tier_fr,
        credential_root,
    ];

    let valid = match Groth16::<Bn254>::verify(&state.vk, &public_inputs, &proof) {
        Ok(v) => v,
        Err(_) => return rejected("proof verification errored (malformed proof)"),
    };
    if !valid {
        return rejected("proof does not verify against this relay's verifying key");
    }

    // Re-derive the hex keys from the parsed Fr rather than trusting the
    // request's original casing/formatting, so two textually-different but
    // field-equal encodings can't split one indicator's score across keys.
    let indicator_key = fr_to_hex(&indicator_hash);
    let nullifier_key = fr_to_hex(&nullifier);
    let credential_root_key = fr_to_hex(&credential_root);

    // The circuit now cryptographically enforces `credential_tier >=
    // min_tier` — but only *relative to whichever credential tree
    // `credential_root` names*. That proves internal consistency, not
    // that the tree was honestly vetted by a real issuer: anyone can
    // build their own throwaway credential tree (e.g. with the same
    // `umbra-relay-prove` tooling) and claim any tier they like against
    // it. So the claimed tier is only trusted for scoring weight when
    // `credential_root` is in this relay's configured allowlist of known
    // issuer roots; otherwise (including the Phase 0 default of an empty
    // allowlist — no real issuer exists yet) every observation scores as
    // tier 0, same as before the tier gadget existed. See module docs and
    // docs/THREAT_MODEL.md.
    let tier = if state
        .trusted_credential_roots
        .contains(&credential_root_key)
    {
        req.min_tier
    } else {
        0
    };

    let observation = VerifiedObservation {
        indicator_hash: indicator_key.clone(),
        epoch: req.epoch,
        nullifier: nullifier_key,
        tier,
    };

    let mut inner = state.inner.lock().expect("relay state mutex poisoned");
    let result = accumulate(&[observation], &mut inner.seen_nullifiers, &state.weights);

    if !result.rejected_replays.is_empty() {
        return rejected("nullifier already seen — this observation was already counted");
    }

    for (key, delta) in result.scores {
        *inner.scores.entry(key).or_insert(0) += delta;
    }
    *inner
        .proof_counts
        .entry((indicator_key.clone(), req.epoch))
        .or_insert(0) += 1;

    let score = inner
        .scores
        .get(&(indicator_key, req.epoch))
        .copied()
        .unwrap_or(0);

    Json(SubmitObservationResponse {
        accepted: true,
        reason: None,
        score: Some(score),
    })
}

#[derive(Debug, Serialize)]
pub struct ScoreResponse {
    pub indicator_hash: String,
    pub epoch: u64,
    pub score: u32,
    pub proof_count: u32,
}

async fn get_score(
    State(state): State<Arc<AppState>>,
    Path((indicator_hash, epoch)): Path<(String, u64)>,
) -> Json<ScoreResponse> {
    let inner = state.inner.lock().expect("relay state mutex poisoned");
    let key = (indicator_hash.clone(), epoch);
    Json(ScoreResponse {
        score: inner.scores.get(&key).copied().unwrap_or(0),
        proof_count: inner.proof_counts.get(&key).copied().unwrap_or(0),
        indicator_hash,
        epoch,
    })
}
