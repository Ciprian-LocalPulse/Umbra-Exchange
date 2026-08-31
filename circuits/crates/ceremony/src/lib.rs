//! Groth16 Phase 2 (circuit-specific) trusted-setup MPC ceremony
//! machinery, ported from celo-org/snark-setup (a fork of
//! kobigurk/phase2-bn254, the reference BGM17 implementation used for
//! Tornado Cash's, Semaphore's, and others' real ceremonies) to modern
//! arkworks 0.4.
//!
//! **Not independently audited.** Ported carefully, cross-checked against
//! the reference source line-for-line, and tested — but "carefully
//! ported by one contributor" is not a substitute for independent review,
//! especially for code whose entire purpose is producing cryptographic
//! parameters other people will trust. See `docs/CEREMONY.md` for the
//! full picture, including what this crate does and does not cover
//! (notably: real Phase 1 / Powers-of-Tau ingestion is NOT implemented
//! here — see `params::MPCParameters::new_placeholder`'s docs).

pub mod bridge;
pub mod helpers;
pub mod keypair;
pub mod params;
pub mod phase1;

pub use bridge::{from_phase1, required_domain_size, BridgeError};
pub use helpers::{
    check_same_ratio, compute_g2_s, hash_to_g2, merge_pairs, power_pairs, same_ratio,
};
pub use keypair::{hash_cs_pubkeys, Keypair, PrivateKey, PublicKey};
pub use params::{verify_transcript, CeremonyError, MPCParameters};
// phase1's PublicKey/PrivateKey/Keypair intentionally are NOT re-exported
// here — they'd collide with the Phase 2 types above. Access them via
// `ceremony::phase1::PublicKey` etc.
