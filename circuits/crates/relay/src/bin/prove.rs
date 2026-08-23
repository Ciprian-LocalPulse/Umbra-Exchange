//! umbra-relay-prove — reference/demo prover. Builds one real Groth16
//! proof-of-observation proof and prints the JSON body for
//! `POST /v1/observations` to stdout.
//!
//! This is NOT the shape a production contributor client would take: it
//! builds its own throwaway 4-leaf indicator tree AND its own throwaway
//! 4-leaf credential tree on the spot, rather than reading a real,
//! previously-published epoch tree and a real issuer's credential tree
//! (see docs/PROTOCOL_SPEC.md for the real prover flow, and relay's lib.rs
//! docs for why a self-issued credential tree won't get trusted-tier
//! weighting from a relay that doesn't have this tool's throwaway root in
//! its trusted-roots file). It exists so the whole keygen -> prove ->
//! submit -> score loop can be exercised end to end without a real
//! contributor/issuer pipeline yet.
//!
//! Usage: `umbra-relay-prove <path-to-umbra.pk> [indicator] [epoch] [claimed-min-tier] [actual-credential-tier]`
//! `actual-credential-tier` defaults to `claimed-min-tier` (an honest
//! proof). Pass a lower value than `claimed-min-tier` to build a proof
//! that *should* fail to verify — useful for demonstrating the
//! credential-tier gate rejects unbacked claims.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use proof_of_observation::indicator::indicator_hash_from_raw;
use proof_of_observation::test_support::sample_observation;
use rand::{rngs::StdRng, SeedableRng};
use relay::encoding::{fr_to_hex, proof_to_hex};
use std::fs;

fn main() {
    let pk_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "umbra.pk".to_string());
    let indicator = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "example.com".to_string());
    let epoch: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20260822);
    let claimed_min_tier: u64 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let actual_credential_tier: u64 = std::env::args()
        .nth(5)
        .and_then(|s| s.parse().ok())
        .unwrap_or(claimed_min_tier);

    let pk_bytes = fs::read(&pk_path)
        .unwrap_or_else(|e| panic!("reading {pk_path}: {e} — run umbra-relay-keygen first"));
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .expect("umbra.pk is not a valid Groth16 proving key");

    // Uses the same canonical string->Fr hash the relay checks disclosures
    // against (proof_of_observation::indicator::indicator_hash_from_raw) —
    // using anything else here would make this tool's own `indicator`
    // disclosure field always get rejected by a relay for hash mismatch.
    let indicator_hash = indicator_hash_from_raw(&indicator);
    let epoch_fr = Fr::from(epoch);
    let salt = Fr::from(rand::random::<u64>());
    let credential_secret = Fr::from(rand::random::<u64>());
    let credential_tier = Fr::from(actual_credential_tier);
    let min_tier = Fr::from(claimed_min_tier);

    let sample = sample_observation(
        indicator_hash,
        epoch_fr,
        salt,
        credential_secret,
        credential_tier,
        min_tier,
    );

    if actual_credential_tier < claimed_min_tier {
        eprintln!(
            "note: actual credential tier ({actual_credential_tier}) is below the claimed \
             min_tier ({claimed_min_tier}) — proving should fail, on purpose, to demonstrate \
             the credential-tier gate."
        );
    }

    let mut rng = StdRng::from_entropy();
    let proof = Groth16::<Bn254>::prove(&pk, sample.circuit, &mut rng)
        .expect("proving should succeed with a valid witness");

    let body = serde_json::json!({
        "indicator_hash": fr_to_hex(&sample.public.indicator_hash),
        "epoch": epoch,
        "root": fr_to_hex(&sample.public.root),
        "nullifier": fr_to_hex(&sample.public.nullifier),
        "min_tier": claimed_min_tier,
        "credential_root": fr_to_hex(&sample.public.credential_root),
        "indicator": indicator,
        "proof": proof_to_hex(&proof),
    });

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    eprintln!("\nPOST the JSON above to {{relay}}/v1/observations to submit it.");
    eprintln!(
        "(credential_root is a throwaway tree this tool built itself — a relay will only \
         trust the tier claim if this root is in its --trusted-roots file.)"
    );
}
