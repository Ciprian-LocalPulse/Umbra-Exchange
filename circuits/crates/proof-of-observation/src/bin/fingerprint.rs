//! Computes a stable fingerprint of `ProofOfObservationCircuit`'s R1CS
//! constraint-system shape, so every participant in a trusted-setup
//! ceremony (and anyone verifying its output afterward) can confirm
//! they're all working from the exact same circuit definition — not a
//! subtly different one that happens to have the same variable counts.
//!
//! This does NOT touch any MPC/ceremony cryptography — it only hashes the
//! circuit's shape using ark-relations' own already-tested constraint
//! system machinery (`to_matrices`) and a standard hash function. See
//! `docs/CEREMONY.md` for how this fits into the actual ceremony process,
//! and why this repo doesn't (yet) ship the ceremony's Phase 2 MPC
//! contribution/verification code itself.
//!
//! Usage: `cargo run -p proof-of-observation --features test-support --bin fingerprint`

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use proof_of_observation::test_support::sample_observation;
use sha2::{Digest, Sha512};

fn main() {
    // The specific values here don't affect the constraint system's
    // *shape* (only witness values would, and only the shape gets
    // fingerprinted below) — any well-formed sample works. Uses the same
    // 4-leaf/depth-2 tree construction every tool in this workspace uses;
    // see docs/CEREMONY.md's note on why tree depth needs to be a
    // deliberately-fixed protocol parameter before a real ceremony runs.
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );

    let cs = ConstraintSystem::<Fr>::new_ref();
    sample
        .circuit
        .generate_constraints(cs.clone())
        .expect("a well-formed sample circuit must synthesize cleanly");
    cs.finalize();

    let matrices = cs
        .to_matrices()
        .expect("a finalized constraint system must produce matrices");

    // Fingerprint the actual matrix entries, not just the summary counts
    // printed below — two circuits could coincidentally share constraint
    // counts while computing genuinely different constraints, and only
    // hashing the counts would miss that.
    let mut hasher = Sha512::new();
    for matrix in [&matrices.a, &matrices.b, &matrices.c] {
        hasher.update((matrix.len() as u64).to_le_bytes());
        for row in matrix {
            hasher.update((row.len() as u64).to_le_bytes());
            for (coeff, index) in row {
                hasher.update((*index as u64).to_le_bytes());
                let mut coeff_bytes = Vec::new();
                coeff
                    .serialize_compressed(&mut coeff_bytes)
                    .expect("field element serialization is infallible");
                hasher.update(&coeff_bytes);
            }
        }
    }
    let hash = hasher.finalize();

    println!("ProofOfObservationCircuit fingerprint (SHA-512 of R1CS matrices):");
    println!("{}", hex::encode(hash));
    println!();
    println!("num_constraints:         {}", matrices.num_constraints);
    println!(
        "num_instance_variables:  {}",
        matrices.num_instance_variables
    );
    println!(
        "num_witness_variables:   {}",
        matrices.num_witness_variables
    );
    println!();
    println!(
        "Every ceremony participant must confirm this exact hash before contributing — see docs/CEREMONY.md."
    );
}
