//! `ceremony-init` — builds the starting point for a Phase 2 ceremony for
//! `ProofOfObservationCircuit`. Writes an `MPCParameters` file with zero
//! contributions yet.
//!
//! IMPORTANT: see `ceremony`'s crate-level docs and `docs/CEREMONY.md`.
//! `MPCParameters::new_placeholder` samples alpha/beta/gamma locally —
//! this is NOT a substitute for real Phase 1 ceremony output. What this
//! tool produces is only ready for the delta-recontribution chain below
//! to be exercised correctly; it does not by itself make the resulting
//! parameters trustworthy.
//!
//! Usage: `cargo run -p ceremony --features test-support --bin ceremony-init -- <output-path>`

use ark_bn254::{Bn254, Fr};
use ark_std::rand::rngs::OsRng;
use ceremony::MPCParameters;
use proof_of_observation::test_support::sample_observation;
use std::fs::File;

fn main() {
    let output_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ceremony.params".to_string());

    eprintln!(
        "ceremony-init: building a PLACEHOLDER starting point (alpha/beta/gamma sampled \
         locally, NOT from a real Phase 1 ceremony). Every subsequent contribution's delta \
         re-randomization is real; the fields this step samples are not — see \
         docs/CEREMONY.md before treating this ceremony's output as trustworthy."
    );

    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );

    let mut rng = OsRng;
    let params = MPCParameters::<Bn254>::new_placeholder(sample.circuit, &mut rng)
        .expect("building placeholder parameters for a well-formed circuit must succeed");

    let mut file =
        File::create(&output_path).unwrap_or_else(|e| panic!("creating {output_path}: {e}"));
    params
        .write(&mut file)
        .expect("writing ceremony parameters must succeed");

    eprintln!(
        "wrote {output_path} — cs_hash: {}",
        hex::encode(params.cs_hash)
    );
    eprintln!("Every participant must confirm this cs_hash matches before contributing.");
}
