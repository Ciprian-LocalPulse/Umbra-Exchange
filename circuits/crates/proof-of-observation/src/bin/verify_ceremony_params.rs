//! Sanity-checks a Groth16 `(proving key, verifying key)` pair — produced
//! by *any* setup process, a real ceremony, `umbra-relay-keygen`, or
//! anything else — against `ProofOfObservationCircuit`.
//!
//! This does NOT verify that a multi-party ceremony's contribution
//! protocol was itself executed honestly; that needs whichever Phase 2
//! tool's own transcript verification (see `docs/CEREMONY.md`, which also
//! explains why this repo doesn't ship that part yet). What this DOES
//! catch is a different, real, and easy-to-make class of mistake: a
//! corrupted file, a pk/vk pair that don't actually correspond to each
//! other, parameters generated for the wrong circuit or the wrong curve.
//! Run this on any ceremony's output before trusting it, in addition to
//! (not instead of) verifying the ceremony's own contribution transcript.
//!
//! Usage:
//! `cargo run -p proof-of-observation --features test-support --bin verify-ceremony-params -- <pk-path> <vk-path>`

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use proof_of_observation::test_support::sample_observation;
use rand::rngs::OsRng;
use std::fs;

fn main() {
    let mut args = std::env::args().skip(1);
    let pk_path = args
        .next()
        .expect("usage: verify-ceremony-params <pk-path> <vk-path>");
    let vk_path = args
        .next()
        .expect("usage: verify-ceremony-params <pk-path> <vk-path>");

    let pk_bytes = fs::read(&pk_path).unwrap_or_else(|e| panic!("reading {pk_path}: {e}"));
    let vk_bytes = fs::read(&vk_path).unwrap_or_else(|e| panic!("reading {vk_path}: {e}"));

    // Checked (not unchecked) deserialization: validates every group
    // element is actually on the curve and in the correct subgroup. This
    // tool exists specifically to catch that class of problem — using the
    // faster unchecked variant here would defeat the entire point.
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .expect("pk file is not a well-formed, valid Groth16 proving key");
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .expect("vk file is not a well-formed, valid Groth16 verifying key");

    println!("Both files deserialized as well-formed, valid Groth16 parameters.");

    let sample = sample_observation(
        Fr::from(12345u64),
        Fr::from(20260822u64),
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(1u64),
        Fr::from(1u64),
    );
    let mut rng = OsRng;
    let proof = Groth16::<Bn254>::prove(&pk, sample.circuit, &mut rng)
        .expect("proving with this pk against ProofOfObservationCircuit must succeed");
    let valid = Groth16::<Bn254>::verify(&vk, &sample.public_inputs_vec, &proof)
        .expect("verification must not error");

    if valid {
        println!(
            "Round-trip OK: a real proof built with this pk verifies against this vk for \
             ProofOfObservationCircuit."
        );
    } else {
        panic!(
            "pk and vk do not correspond to the same circuit/parameters — DO NOT use this pair."
        );
    }
}
