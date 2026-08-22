//! umbra-relay — reference relay server (see docs/ARCHITECTURE.md).
//! Verifies proof-of-observation Groth16 proofs, rejects nullifier
//! replays, aggregates per-(indicator, epoch) confidence scores.
//!
//! Phase 0: in-memory only, single instance, and only as trustworthy as
//! the verifying key it's started with — see `umbra-relay-keygen`'s
//! warning banner before pointing this at anything real.
//!
//! Usage: `umbra-relay [path-to-umbra.vk] [listen-addr]`
//! Defaults: `umbra.vk` in the current directory, `127.0.0.1:8080`.

use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use relay::state::AppState;
use reputation_accumulator::TierWeights;
use std::fs;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let vk_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "umbra.vk".to_string());
    let addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let vk_bytes = fs::read(&vk_path)
        .unwrap_or_else(|e| panic!("reading {vk_path}: {e} — run umbra-relay-keygen first"));
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .expect("umbra.vk is not a valid Groth16 verifying key");

    let state = Arc::new(AppState::new(vk, TierWeights::default_weights()));
    let app = relay::router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("binding {addr}: {e}"));
    eprintln!("umbra-relay listening on http://{addr}");
    eprintln!("(Phase 0 reference relay — see docs/THREAT_MODEL.md before real use.)");

    axum::serve(listener, app)
        .await
        .expect("relay server error");
}
