//! `ceremony-contribute` — applies one contributor's fresh randomness to
//! an in-progress ceremony file, in place.
//!
//! CRITICAL: the randomness this consumes is destroyed when this process
//! exits (Rust drops it, and `PrivateKey` zeroizes on drop — see
//! `keypair.rs`) — but that only protects against *this process's own
//! memory* being inspected after the fact. It does NOT protect against a
//! compromised machine, a memory dump taken *during* the run, swap files,
//! core dumps, or a malicious build of this very binary. Run this on a
//! machine and OS you trust, ideally offline, and reboot or securely wipe
//! it afterward if this contribution matters. See docs/CEREMONY.md.
//!
//! Usage: `cargo run -p ceremony --bin ceremony-contribute -- <params-file>`
//! (mutates the file in place; back it up first if you want the
//! pre-contribution state preserved)

use ark_bn254::Bn254;
use ark_std::rand::rngs::OsRng;
use ceremony::MPCParameters;
use std::fs::File;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: ceremony-contribute <params-file>");

    let file = File::open(&path).unwrap_or_else(|e| panic!("opening {path}: {e}"));
    let mut params =
        MPCParameters::<Bn254>::read(file).unwrap_or_else(|e| panic!("reading {path}: {e}"));

    eprintln!(
        "read {path}: cs_hash {}, {} prior contribution(s)",
        hex::encode(params.cs_hash),
        params.contributions.len()
    );
    eprintln!(
        "CONFIRM the cs_hash above matches what the ceremony coordinator published before \
         continuing — contributing to the wrong circuit produces parameters nobody can use."
    );

    let mut rng = OsRng;
    let contribution_hash = params
        .contribute(&mut rng)
        .expect("contribution must succeed for a well-formed ceremony file");

    let file = File::create(&path).unwrap_or_else(|e| panic!("writing {path}: {e}"));
    params
        .write(file)
        .expect("writing the updated ceremony file must succeed");

    eprintln!("contribution applied. Your contribution's hash (publish this as your attestation):");
    eprintln!("{}", hex::encode(contribution_hash));
    eprintln!(
        "Your secret randomness for this contribution has been dropped (and zeroized) — it \
         cannot be recovered from this process anymore. See this binary's own doc comment for \
         what that does and doesn't protect against."
    );
}
