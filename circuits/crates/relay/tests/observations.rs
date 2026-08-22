//! Integration tests for the relay's HTTP surface. These build *real*
//! Groth16 proofs (via `proof_of_observation::test_support`) and drive the
//! actual `axum::Router` in-process with `tower::ServiceExt::oneshot` — no
//! real TCP socket, but no shortcuts on the cryptography either.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use proof_of_observation::test_support::sample_observation;
use rand::rngs::OsRng;
use relay::encoding::{fr_to_hex, proof_to_hex};
use relay::state::AppState;
use reputation_accumulator::TierWeights;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

/// One local (test-only) Groth16 keypair, shared by every test in this
/// file's setup — mirrors how `umbra-relay-keygen` and `umbra-relay-prove`
/// share a keypair via files in real usage, just without touching disk.
struct Fixture {
    pk: ark_groth16::ProvingKey<Bn254>,
    app: axum::Router,
}

fn setup() -> Fixture {
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let mut rng = OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(sample.circuit, &mut rng)
        .expect("local setup should succeed for a well-formed circuit");

    let state = Arc::new(AppState::new(vk, TierWeights::default_weights()));
    let app = relay::router(state);
    Fixture { pk, app }
}

/// Builds a real, valid submit-observation JSON body for the given
/// indicator/epoch/tier claim, using a freshly-random credential secret
/// (i.e. *not* tied to any real credential — deliberately, since that's
/// exactly the gap the min_tier test below needs to exercise).
fn build_request_body(
    pk: &ark_groth16::ProvingKey<Bn254>,
    indicator: u64,
    epoch: u64,
    claimed_tier: u64,
) -> Value {
    let indicator_hash = Fr::from(indicator);
    let epoch_fr = Fr::from(epoch);
    let salt = Fr::from(rand::random::<u64>());
    let credential_secret = Fr::from(rand::random::<u64>());
    let min_tier = Fr::from(claimed_tier);

    let sample = sample_observation(indicator_hash, epoch_fr, salt, credential_secret, min_tier);
    let mut rng = OsRng;
    let proof =
        Groth16::<Bn254>::prove(pk, sample.circuit, &mut rng).expect("proving should succeed");

    json!({
        "indicator_hash": fr_to_hex(&sample.public.indicator_hash),
        "epoch": epoch,
        "root": fr_to_hex(&sample.public.root),
        "nullifier": fr_to_hex(&sample.public.nullifier),
        "min_tier": claimed_tier,
        "proof": proof_to_hex(&proof),
    })
}

async fn post_observation(app: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/observations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn get_score(app: &axum::Router, indicator_hash_hex: &str, epoch: u64) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/score/{indicator_hash_hex}/{epoch}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn valid_proof_is_accepted_and_scored_at_tier_zero() {
    let fx = setup();
    let body = build_request_body(&fx.pk, 111, 20260822, 0);

    let (status, resp) = post_observation(&fx.app, &body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);
    // TierWeights::default_weights()[0] == 1.
    assert_eq!(resp["score"], 1);
}

/// Regression test for the vulnerability this module's `submit_observation`
/// doc comment warns about: a caller claiming a high `min_tier` with no
/// real credential behind it must NOT receive that tier's weight. Before
/// this was fixed, this exact request scored 8 (the tier-3 weight) instead
/// of 1 (the tier-0 weight) — see the module docs for why.
#[tokio::test]
async fn claimed_high_tier_is_not_trusted_for_scoring_weight() {
    let fx = setup();
    // claimed_tier = 3 (weight 8), but credential_secret is random — no
    // real credential backs this claim, and the circuit doesn't check it.
    let body = build_request_body(&fx.pk, 222, 20260822, 3);

    let (status, resp) = post_observation(&fx.app, &body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);
    assert_eq!(
        resp["score"], 1,
        "an unbacked min_tier=3 claim must score as tier 0 (weight 1), not tier 3 (weight 8)"
    );
}

#[tokio::test]
async fn replayed_nullifier_is_rejected_and_does_not_inflate_score() {
    let fx = setup();
    let body = build_request_body(&fx.pk, 333, 20260822, 0);
    let indicator_hash_hex = body["indicator_hash"].as_str().unwrap().to_string();

    let (first_status, first) = post_observation(&fx.app, &body).await;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first["accepted"], true);

    let (second_status, second) = post_observation(&fx.app, &body).await;
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(second["accepted"], false);
    assert!(second["reason"].as_str().unwrap().contains("already seen"));

    let score = get_score(&fx.app, &indicator_hash_hex, 20260822).await;
    assert_eq!(score["score"], 1, "the replay must not add a second point");
    assert_eq!(score["proof_count"], 1);
}

#[tokio::test]
async fn tampered_proof_is_rejected() {
    let fx = setup();
    let mut body = build_request_body(&fx.pk, 444, 20260822, 0);
    // Flip the epoch in the request without re-proving: the proof was
    // built for epoch 20260822, so this must fail verification.
    body["epoch"] = json!(999u64);

    let (status, resp) = post_observation(&fx.app, &body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], false);
}

#[tokio::test]
async fn distinct_contributors_accumulate_for_the_same_indicator() {
    let fx = setup();
    let a = build_request_body(&fx.pk, 555, 20260822, 0);
    let b = build_request_body(&fx.pk, 555, 20260822, 0);

    let (_, resp_a) = post_observation(&fx.app, &a).await;
    let (_, resp_b) = post_observation(&fx.app, &b).await;

    assert_eq!(resp_a["accepted"], true);
    assert_eq!(resp_b["accepted"], true);
    // Two distinct tier-0 observations for the same indicator: 1 + 1 = 2.
    assert_eq!(resp_b["score"], 2);
}

#[tokio::test]
async fn score_endpoint_returns_zero_for_unknown_indicator() {
    let fx = setup();
    let resp = get_score(&fx.app, &fr_to_hex(&Fr::from(999999u64)), 1).await;
    assert_eq!(resp["score"], 0);
    assert_eq!(resp["proof_count"], 0);
}
