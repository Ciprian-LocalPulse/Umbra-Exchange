//! umbra-relay-prove — reference/demo prover. Builds one real Groth16
//! proof-of-observation proof and prints the JSON body for
//! `POST /v1/observations` to stdout.
//!
//! This is NOT the shape a production contributor client would take: it
//! builds its own throwaway 4-leaf Merkle tree on the spot rather than
//! reading a real, previously-published epoch tree (see
//! docs/PROTOCOL_SPEC.md for the real prover flow). It exists so the whole
//! keygen -> prove -> submit -> score loop can be exercised end to end
//! without a real contributor pipeline yet.
//!
//! Usage: `umbra-relay-prove <path-to-umbra.pk> [indicator] [epoch] [tier]`

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
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
    let tier: u64 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let pk_bytes = fs::read(&pk_path)
        .unwrap_or_else(|e| panic!("reading {pk_path}: {e} — run umbra-relay-keygen first"));
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .expect("umbra.pk is not a valid Groth16 proving key");

    // Demo-only indicator normalization: hash the raw string into a field
    // element directly. A real deployment needs to fix this precisely in
    // docs/PROTOCOL_SPEC.md so every contributor and verifier agrees on
    // the same normalization (e.g. defanged form, case-folding, etc.).
    let indicator_hash = Fr::from_le_bytes_mod_order(indicator.as_bytes());
    let epoch_fr = Fr::from(epoch);
    let salt = Fr::from(rand::random::<u64>());
    let credential_secret = Fr::from(rand::random::<u64>());
    let min_tier = Fr::from(tier);

    let sample = sample_observation(indicator_hash, epoch_fr, salt, credential_secret, min_tier);

    let mut rng = StdRng::from_entropy();
    let proof = Groth16::<Bn254>::prove(&pk, sample.circuit, &mut rng)
        .expect("proving should succeed with a valid witness");

    let body = serde_json::json!({
        "indicator_hash": fr_to_hex(&sample.public.indicator_hash),
        "epoch": epoch,
        "root": fr_to_hex(&sample.public.root),
        "nullifier": fr_to_hex(&sample.public.nullifier),
        "min_tier": tier,
        "proof": proof_to_hex(&proof),
    });

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    eprintln!("\nPOST the JSON above to {{relay}}/v1/observations to submit it.");
}
