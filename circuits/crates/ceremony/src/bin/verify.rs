//! `ceremony-verify` — verifies an entire ceremony's contribution chain
//! from a single final params file, by recomputing and checking every
//! contribution's transcript and signature of knowledge (see
//! `ceremony::params::verify_transcript`, which this calls into).
//!
//! Unlike `MPCParameters::verify` (which checks exactly one hop between
//! two specific snapshots), this checks a whole finished chain from one
//! file — the shape a real coordinator's final published output takes.
//!
//! This does NOT verify that `alpha`/`beta`/`gamma` came from a real
//! Phase 1 ceremony — this crate doesn't implement Phase 1 ingestion; see
//! `docs/CEREMONY.md`. It verifies that the delta-recontribution chain on
//! top of whatever starting point was used is internally consistent and
//! that every contribution's signature of knowledge is valid.
//!
//! Usage: `cargo run -p ceremony --bin ceremony-verify -- <params-file>`

use ark_bn254::Bn254;
use ceremony::{verify_transcript, MPCParameters};
use std::fs::File;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: ceremony-verify <params-file>");

    let file = File::open(&path).unwrap_or_else(|e| panic!("opening {path}: {e}"));
    let params =
        MPCParameters::<Bn254>::read(file).unwrap_or_else(|e| panic!("reading {path}: {e}"));

    println!("cs_hash: {}", hex::encode(params.cs_hash));
    println!(
        "{} contribution(s) in this file's history.",
        params.contributions.len()
    );

    if params.contributions.is_empty() {
        println!("No contributions yet — this is a freshly-initialized ceremony file.");
        return;
    }

    match verify_transcript::<Bn254>(params.cs_hash, &params.contributions) {
        Ok(hashes) => {
            println!(
                "VALID — every contribution's transcript and signature of knowledge checks out."
            );
            println!("Contribution hashes, in order:");
            for (i, h) in hashes.iter().enumerate() {
                println!("  {}: {}", i + 1, hex::encode(h));
            }
        }
        Err(e) => {
            eprintln!("INVALID: {e}");
            std::process::exit(1);
        }
    }
}
