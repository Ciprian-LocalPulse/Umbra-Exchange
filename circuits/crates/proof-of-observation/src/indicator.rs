//! Canonical indicator normalization and string→field hashing.
//!
//! `PublicInputs::indicator_hash` (in this crate's `lib.rs`) is an opaque
//! `Fr` as far as the circuit is concerned — the circuit never sees the
//! raw indicator string, only whatever field element the prover claims.
//! How a raw string like `"HTTP://Example.com/"` maps to that field
//! element is a protocol convention the circuit doesn't enforce, but every
//! prover and every verifier that wants to *disclose* an indicator (as
//! opposed to just proving membership of an opaque commitment) needs to
//! agree on. This module is that convention.
//!
//! ## Why not just `Fr::from_le_bytes_mod_order(bytes)`?
//!
//! `ark_ff::PrimeField::from_le_bytes_mod_order` already handles
//! arbitrary-length byte slices (it's a running modular reduction, not a
//! truncation), so it would "work" without truncation bugs. But it's a
//! byte encoding, not a hash: `docs/PROTOCOL_SPEC.md` specifies
//! `indicator_hash: Poseidon(normalized_indicator)`, and an encoding with
//! no hiding/mixing property doesn't satisfy that even though it happens
//! to produce a well-defined field element. This module builds an actual
//! Poseidon-based hash instead, by chunking the normalized string into
//! ≤31-byte pieces (each safely `< Fr`'s modulus) and folding them through
//! the same 2-to-1 Poseidon compression (`poseidon_params::merkle_node_config`)
//! this crate already uses for Merkle nodes — deliberately reusing an
//! already-parameterized primitive rather than defining a new one. This is
//! a standard Merkle–Damgård-style construction (how e.g. SHA-256 itself
//! is built from a compression function), not a novel cryptographic
//! primitive; the only non-obvious piece is folding the byte length in as
//! a final block, which is standard MD-strengthening against
//! prefix/length-extension collisions (e.g. `"ab"` vs `"ab" + "\0"`-style
//! ambiguity).
//!
//! ## Normalization
//!
//! Deliberately conservative for Phase 1: trim whitespace, lowercase.
//! Correct and safe for hashes (hex is case-insensitive) and domains
//! (case-insensitive per DNS), and harmless for IPs (already lowercase).
//! It does NOT do IOC-type-specific canonicalization yet — e.g. no
//! defanging (`example[.]com` -> `example.com`), no URL trailing-slash or
//! percent-encoding normalization, no IPv6 zero-compression normalization.
//! Two indicators that a human would consider "the same" but that differ
//! in one of those ways will currently hash differently and be tracked as
//! separate indicators. Documented here rather than silently handled so
//! it's an obvious, findable gap rather than a surprise.

use crate::poseidon_params;
use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_ff::PrimeField;

/// See module docs. Trim + lowercase only, for now.
pub fn normalize_indicator(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// BN254's scalar field modulus is ~254 bits; 31 bytes (248 bits) is the
/// largest chunk size that's guaranteed to fit without ambiguity for any
/// byte content (32 bytes could, depending on value, meet or exceed the
/// modulus and get silently reduced, which would make two different
/// 32-byte chunks hash the same — 31 bytes avoids that entirely).
const CHUNK_BYTES: usize = 31;

/// Maps a raw indicator string to the `Fr` used as `PublicInputs::indicator_hash`
/// and as a leaf/nullifier input throughout the circuit. See module docs
/// for the construction and its rationale.
pub fn indicator_hash_from_raw(raw: &str) -> Fr {
    let normalized = normalize_indicator(raw);
    let bytes = normalized.as_bytes();
    let node_cfg = poseidon_params::merkle_node_config();

    let mut acc = Fr::from(0u64);
    for chunk in bytes.chunks(CHUNK_BYTES) {
        let chunk_fr = Fr::from_le_bytes_mod_order(chunk);
        acc = TwoToOneCRH::<Fr>::compress(&node_cfg, acc, chunk_fr)
            .expect("Poseidon compression over a well-formed Fr pair cannot fail");
    }
    // MD-strengthening: fold in the byte length as a final block so that
    // e.g. a string and a length-extended variant of it can't collide by
    // continuing the chunk sequence identically.
    let len_fr = Fr::from(bytes.len() as u64);
    TwoToOneCRH::<Fr>::compress(&node_cfg, acc, len_fr)
        .expect("Poseidon compression over a well-formed Fr pair cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_string_hashes_the_same() {
        assert_eq!(
            indicator_hash_from_raw("evil.example"),
            indicator_hash_from_raw("evil.example")
        );
    }

    #[test]
    fn normalization_makes_case_and_whitespace_irrelevant() {
        assert_eq!(
            indicator_hash_from_raw("Evil.Example"),
            indicator_hash_from_raw("  evil.example  ")
        );
    }

    #[test]
    fn different_strings_hash_differently() {
        assert_ne!(
            indicator_hash_from_raw("evil.example"),
            indicator_hash_from_raw("evil2.example")
        );
    }

    #[test]
    fn prefix_strings_do_not_collide() {
        // Without MD-strengthening (folding in the length), a naive
        // chunk-by-chunk fold risks exactly this kind of prefix collision
        // between short strings and their extensions.
        assert_ne!(indicator_hash_from_raw("ab"), indicator_hash_from_raw("a"));
        assert_ne!(
            indicator_hash_from_raw("ab"),
            indicator_hash_from_raw("abc")
        );
    }

    #[test]
    fn long_strings_spanning_multiple_chunks_do_not_panic_and_differ() {
        let a = "a".repeat(100);
        let b = format!("{a}b");
        assert_ne!(indicator_hash_from_raw(&a), indicator_hash_from_raw(&b));
    }

    #[test]
    fn empty_string_does_not_panic() {
        let _ = indicator_hash_from_raw("");
    }
}
