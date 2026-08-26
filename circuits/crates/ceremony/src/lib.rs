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

pub mod helpers;
pub mod keypair;
pub mod params;

pub use helpers::{check_same_ratio, hash_to_g2, merge_pairs, same_ratio};
pub use keypair::{hash_cs_pubkeys, Keypair, PrivateKey, PublicKey};
pub use params::{verify_transcript, CeremonyError, MPCParameters};
