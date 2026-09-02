//! Integration tests for the relay's HTTP surface. These build *real*
//! Groth16 proofs (via `proof_of_observation::test_support`) and drive the
//! actual `axum::Router` in-process with `tower::ServiceExt::oneshot` — no
//! real TCP socket, but no shortcuts on the cryptography either.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use proof_of_observation::indicator::indicator_hash_from_raw;
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
/// and an *honest* credential (actual tier == claimed tier) in a
/// throwaway credential tree. Since `setup()`'s relay starts with an
/// empty trusted-roots set, every request built this way still scores as
/// tier 0 regardless of the claim — see
/// `claimed_high_tier_is_not_trusted_for_scoring_weight` below, which
/// exercises exactly that.
fn build_request_body(
    pk: &ark_groth16::ProvingKey<Bn254>,
    indicator: u64,
    epoch: u64,
    claimed_tier: u64,
) -> Value {
    build_request_body_with_credential(pk, indicator, epoch, claimed_tier, claimed_tier)
}

/// Same as `build_request_body`, but lets the caller set the *actual*
/// credential tier independently of the *claimed* tier — so tests can
/// build proofs where the two disagree, in either direction. When they
/// disagree unfavorably (actual < claimed), the circuit itself should
/// refuse to produce a satisfying proof.
fn build_request_body_with_credential(
    pk: &ark_groth16::ProvingKey<Bn254>,
    indicator: u64,
    epoch: u64,
    claimed_tier: u64,
    actual_credential_tier: u64,
) -> Value {
    let indicator_hash = Fr::from(indicator);
    let epoch_fr = Fr::from(epoch);
    let salt = Fr::from(rand::random::<u64>());
    let credential_secret = Fr::from(rand::random::<u64>());
    let min_tier = Fr::from(claimed_tier);
    let credential_tier = Fr::from(actual_credential_tier);

    let sample = sample_observation(
        indicator_hash,
        epoch_fr,
        salt,
        credential_secret,
        credential_tier,
        min_tier,
    );
    let mut rng = OsRng;
    let proof =
        Groth16::<Bn254>::prove(pk, sample.circuit, &mut rng).expect("proving should succeed");

    json!({
        "indicator_hash": fr_to_hex(&sample.public.indicator_hash),
        "epoch": epoch,
        "root": fr_to_hex(&sample.public.root),
        "nullifier": fr_to_hex(&sample.public.nullifier),
        "min_tier": claimed_tier,
        "credential_root": fr_to_hex(&sample.public.credential_root),
        "proof": proof_to_hex(&proof),
    })
}

/// Same idea as `build_request_body`, but keyed by a raw indicator string
/// (hashed via the same canonical function the relay checks disclosures
/// against) rather than a bare `Fr`, and with control over whether the
/// disclosure field is included — for exercising the disclosure/STIX
/// export path specifically.
fn build_request_body_for_indicator(
    pk: &ark_groth16::ProvingKey<Bn254>,
    raw_indicator: &str,
    epoch: u64,
    claimed_tier: u64,
    disclose: bool,
) -> Value {
    let indicator_hash = indicator_hash_from_raw(raw_indicator);
    let epoch_fr = Fr::from(epoch);
    let salt = Fr::from(rand::random::<u64>());
    let credential_secret = Fr::from(rand::random::<u64>());
    let min_tier = Fr::from(claimed_tier);
    let credential_tier = Fr::from(claimed_tier);

    let sample = sample_observation(
        indicator_hash,
        epoch_fr,
        salt,
        credential_secret,
        credential_tier,
        min_tier,
    );
    let mut rng = OsRng;
    let proof =
        Groth16::<Bn254>::prove(pk, sample.circuit, &mut rng).expect("proving should succeed");

    let mut body = json!({
        "indicator_hash": fr_to_hex(&sample.public.indicator_hash),
        "epoch": epoch,
        "root": fr_to_hex(&sample.public.root),
        "nullifier": fr_to_hex(&sample.public.nullifier),
        "min_tier": claimed_tier,
        "credential_root": fr_to_hex(&sample.public.credential_root),
        "proof": proof_to_hex(&proof),
    });
    if disclose {
        body["indicator"] = json!(raw_indicator);
    }
    body
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

async fn export_stix(app: &axum::Router, threshold: u32) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/export/stix?threshold={threshold}"))
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

async fn export_misp(app: &axum::Router, threshold: u32) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/export/misp?threshold={threshold}"))
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

/// The tier gate is now cryptographically enforced by the circuit itself
/// (an honest, valid tier-3 credential really does prove tier>=3) — but
/// that's relative to *some* credential tree. This relay's `setup()`
/// starts with an empty trusted-roots allowlist (the Phase 0 default: no
/// real issuer exists yet), so even a perfectly valid tier-3 proof must
/// still score as tier 0, because this relay has no reason to trust the
/// specific tree the claim was checked against. See
/// `claim_is_trusted_when_credential_root_is_allowlisted` below for the
/// contrasting case.
#[tokio::test]
async fn claimed_high_tier_is_not_trusted_for_scoring_weight() {
    let fx = setup();
    // An honest tier-3 credential (actual == claimed), but its credential
    // tree is a throwaway this test built itself — not in any allowlist.
    let body = build_request_body(&fx.pk, 222, 20260822, 3);

    let (status, resp) = post_observation(&fx.app, &body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);
    assert_eq!(
        resp["score"], 1,
        "an untrusted credential_root must score as tier 0 (weight 1) even with a valid tier-3 proof"
    );
}

/// Contrasts with the test above: same honest tier-3 proof, but this time
/// the relay's trusted-roots allowlist includes the credential_root the
/// proof was checked against, so the (cryptographically real) tier claim
/// is honored for scoring weight.
#[tokio::test]
async fn claim_is_trusted_when_credential_root_is_allowlisted() {
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let mut rng = OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(sample.circuit, &mut rng)
        .expect("local setup should succeed for a well-formed circuit");

    let body = build_request_body(&pk, 223, 20260822, 3);
    let credential_root_hex = body["credential_root"].as_str().unwrap().to_string();

    let mut trusted = std::collections::HashSet::new();
    trusted.insert(credential_root_hex);
    let state = Arc::new(
        AppState::new(vk, TierWeights::default_weights()).with_trusted_credential_roots(trusted),
    );
    let app = relay::router(state);

    let (status, resp) = post_observation(&app, &body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);
    assert_eq!(
        resp["score"], 8,
        "an honest tier-3 proof against an allowlisted credential_root must score at tier-3 weight"
    );
}

/// The credential-tier gate's actual security property: a *dishonest*
/// claim — actual credential tier below what's claimed — can't even be
/// turned into a proof. `Groth16::prove` asserts constraint satisfaction
/// internally and panics rather than silently emitting a proof that would
/// later fail verification — i.e. the gate fails closed at the earliest
/// possible point, not just at the relay's `Groth16::verify` call. This is
/// the in-circuit counterpart to the (now-historical) relay-layer
/// vulnerability regression-tested elsewhere in this file.
#[test]
#[should_panic(expected = "cs.is_satisfied()")]
fn unbacked_tier_claim_cannot_even_be_proven() {
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let mut setup_rng = OsRng;
    let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(sample.circuit, &mut setup_rng)
        .expect("local setup should succeed for a well-formed circuit");

    // Actual credential tier 0, but claiming tier 3.
    let _ = build_request_body_with_credential(&pk, 224, 20260822, 3, 0);
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

#[tokio::test]
async fn disclosed_indicator_appears_in_stix_export() {
    let fx = setup();
    let body = build_request_body_for_indicator(&fx.pk, "evil.example", 20260822, 0, true);

    let (status, resp) = post_observation(&fx.app, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);

    let bundle = export_stix(&fx.app, 1).await;
    let objects = bundle["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(
        objects[0]["pattern"],
        "[domain-name:value = 'evil.example']"
    );
    assert_eq!(objects[0]["x_umbra_proof_count"], 1);
}

#[tokio::test]
async fn undisclosed_indicator_is_excluded_from_stix_export() {
    let fx = setup();
    // Same indicator, valid proof, but no `indicator` field — never
    // disclosed, so it must never surface as a STIX pattern.
    let body = build_request_body_for_indicator(&fx.pk, "quiet.example", 20260822, 0, false);

    let (status, resp) = post_observation(&fx.app, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        resp["accepted"], true,
        "the proof itself is still valid and scored"
    );

    let bundle = export_stix(&fx.app, 1).await;
    let objects = bundle["objects"].as_array().unwrap();
    assert!(
        objects.is_empty(),
        "an undisclosed indicator must never appear in STIX export, per schema/stix_mapping.md"
    );
}

#[tokio::test]
async fn stix_export_respects_threshold() {
    let fx = setup();
    let body =
        build_request_body_for_indicator(&fx.pk, "belowthreshold.example", 20260822, 0, true);
    let (_, resp) = post_observation(&fx.app, &body).await;
    assert_eq!(resp["score"], 1); // tier-0 weight

    let bundle = export_stix(&fx.app, 5).await;
    assert!(
        bundle["objects"].as_array().unwrap().is_empty(),
        "score 1 must not clear a threshold of 5"
    );

    let bundle = export_stix(&fx.app, 1).await;
    assert_eq!(bundle["objects"].as_array().unwrap().len(), 1);
}

/// Regression test for exactly the attack `submit_observation`'s
/// disclosure-check comment describes: attaching a disclosure that
/// doesn't actually correspond to the proof's real indicator_hash must
/// reject the whole submission, not just the disclosure.
#[tokio::test]
async fn mismatched_disclosure_rejects_the_whole_submission() {
    let fx = setup();
    let mut body = build_request_body_for_indicator(&fx.pk, "real.example", 20260822, 0, true);
    // Swap in a different string than the one actually proven.
    body["indicator"] = json!("fake.example");

    let (status, resp) = post_observation(&fx.app, &body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], false);
    assert!(resp["reason"]
        .as_str()
        .unwrap()
        .contains("does not hash to"));

    // And it must not have been scored at all, disclosed or not.
    let score = get_score(
        &fx.app,
        &fr_to_hex(&indicator_hash_from_raw("real.example")),
        20260822,
    )
    .await;
    assert_eq!(score["score"], 0);
}

#[tokio::test]
async fn disclosed_indicator_appears_in_misp_export() {
    let fx = setup();
    let body = build_request_body_for_indicator(&fx.pk, "misp-evil.example", 20260822, 0, true);

    let (status, resp) = post_observation(&fx.app, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);

    let event = export_misp(&fx.app, 1).await;
    let objects = event["Event"]["Object"].as_array().unwrap();
    assert_eq!(objects.len(), 1);
    let attrs = objects[0]["Attribute"].as_array().unwrap();
    assert_eq!(attrs[0]["type"], "domain");
    assert_eq!(attrs[0]["value"], "misp-evil.example");
}

#[tokio::test]
async fn undisclosed_indicator_is_excluded_from_misp_export() {
    let fx = setup();
    let body = build_request_body_for_indicator(&fx.pk, "misp-quiet.example", 20260822, 0, false);

    let (status, resp) = post_observation(&fx.app, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], true);

    let event = export_misp(&fx.app, 1).await;
    let objects = event["Event"]["Object"].as_array().unwrap();
    assert!(
        objects.is_empty(),
        "an undisclosed indicator must never appear in MISP export either, same as STIX"
    );
}
