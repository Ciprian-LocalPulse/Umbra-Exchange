//! umbra-relay library: HTTP surface + verification/scoring glue for the
//! reference relay described in docs/ARCHITECTURE.md.
//!
//! Split into a library (this crate) plus three thin binaries
//! (`src/bin/server.rs`, `keygen.rs`, `prove.rs`) so the request-handling
//! logic here is unit-testable without a real TCP listener, and so
//! `keygen`/`prove` can reuse it (e.g. `encoding`) without duplicating it.
//!
//! Phase 0 caveats that matter for anyone reading this as a spec: proofs
//! are only checked against whatever verifying key the relay was started
//! with (see `umbra-relay-keygen`'s warning banner — it's a local,
//! non-ceremony setup), and `min_tier` is currently an unconstrained public
//! input in the circuit itself (see proof-of-observation's lib.rs docs), so
//! this relay is trusting the claimed tier, not proving it. Treat this
//! deployment as a research prototype — see docs/THREAT_MODEL.md.

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
    /// Claimed tier (0-3). NOT cryptographically enforced yet — see module
    /// docs and proof-of-observation's lib.rs.
    pub min_tier: u8,
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
    let proof: Proof<Bn254> = match proof_from_hex(&req.proof) {
        Ok(v) => v,
        Err(e) => return rejected(&e.to_string()),
    };

    // Field-element ordering here must match `PublicInputs`'s field order
    // in proof-of-observation's lib.rs (indicator_hash, epoch, root,
    // nullifier, min_tier) — Groth16::verify has no way to catch a
    // silently-reordered public-input vector.
    let epoch_fr = Fr::from(req.epoch);
    let min_tier_fr = Fr::from(req.min_tier as u64);
    let public_inputs = vec![indicator_hash, epoch_fr, root, nullifier, min_tier_fr];

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

    let observation = VerifiedObservation {
        indicator_hash: indicator_key.clone(),
        epoch: req.epoch,
        nullifier: nullifier_key,
        tier: req.min_tier,
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
