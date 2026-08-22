//! umbra-relay-keygen — local (non-ceremony) Groth16 setup for the
//! proof-of-observation circuit.
//!
//! WARNING: this is a *local* trusted setup, run by a single party on a
//! single machine. Whoever runs it retains the setup's "toxic waste" and
//! could, in principle, forge proofs that verify against the resulting
//! key. That's acceptable for local development and testing. It is NOT a
//! substitute for a real multi-party ceremony before this relay is used
//! with real, sensitive threat-intel data — see docs/THREAT_MODEL.md,
//! "Trusted setup". This RNG is deliberately OS-entropy-seeded
//! (`OsRng`), not a fixed seed: a fixed/deterministic seed here would mean
//! the toxic waste is reconstructible by anyone who reads this source
//! file, not just whoever ran the binary — do not "fix" this to be
//! reproducible.
//!
//! Usage: `umbra-relay-keygen [output-dir]` (defaults to the current
//! directory). Writes `umbra.pk` (proving key, for `umbra-relay-prove`)
//! and `umbra.vk` (verifying key, for `umbra-relay-server`).

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use proof_of_observation::test_support::sample_observation;
use rand::rngs::OsRng;
use std::fs;

fn main() {
    eprintln!("umbra-relay-keygen: LOCAL (non-ceremony) setup.");
    eprintln!(
        "Anyone who ran this binary retains the setup's toxic waste and could, in\n\
         principle, forge proofs against the resulting verifying key. Fine for local\n\
         dev/testing; not a substitute for a real ceremony before this relay handles\n\
         real data — see docs/THREAT_MODEL.md, \"Trusted setup\".\n"
    );

    let out_dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());

    // `circuit_specific_setup` only needs the circuit's *shape* (which
    // `sample_observation`'s fixed 4-leaf tree fully determines) — these
    // placeholder values never need to satisfy a real observation, they
    // just need to be well-formed enough to synthesize constraints.
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );

    let mut rng = OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(sample.circuit, &mut rng)
        .expect("local Groth16 setup should succeed for a well-formed circuit");

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .expect("proving key serialization is infallible for a well-formed key");
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .expect("verifying key serialization is infallible for a well-formed key");

    let pk_path = format!("{out_dir}/umbra.pk");
    let vk_path = format!("{out_dir}/umbra.vk");
    fs::write(&pk_path, &pk_bytes).unwrap_or_else(|e| panic!("writing {pk_path}: {e}"));
    fs::write(&vk_path, &vk_bytes).unwrap_or_else(|e| panic!("writing {vk_path}: {e}"));

    eprintln!("wrote {pk_path} ({} bytes)", pk_bytes.len());
    eprintln!("wrote {vk_path} ({} bytes)", vk_bytes.len());
}
