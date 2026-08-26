//! Ported from celo-org/snark-setup's `phase2/src/keypair.rs` to modern
//! arkworks 0.4. Checked line-for-line against that source before
//! writing this. Not independently audited; see `docs/CEREMONY.md`.
//!
//! One deliberate departure from the reference worth noting: the
//! reference serializes prior contributions *uncompressed* when computing
//! `hash_cs_pubkeys`, but this contribution's own `s`/`s_delta`
//! *compressed* — an inconsistency in their own transcript format that
//! doesn't matter for their purposes (it's an internal, self-consistent
//! hash, not required to match any external ceremony's byte format) but
//! isn't worth reproducing here. This port uses compressed serialization
//! uniformly everywhere a value gets hashed. That's still a canonical,
//! unique encoding (which is the actual security-relevant property —
//! any two distinct values must serialize to distinct byte strings), just
//! not byte-identical to the reference's own transcript hashes.

use crate::helpers::hash_to_g2;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use blake2::{Blake2b512, Digest};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The secret that must be destroyed after this contribution is applied.
/// If at least one contributor across a ceremony's entire history
/// destroys this honestly, the resulting parameters are sound — see
/// `docs/CEREMONY.md`. `Zeroize`d on drop (not left to ordinary scope-end
/// deallocation, which doesn't clear memory) — same care this workspace
/// already takes with other secrets (`relay`'s `HolderKey`/`QuerierKey`,
/// `psi`'s equivalents). Caught by `cargo clippy`'s `drop_non_drop` lint
/// firing on a bare `drop(private_key)` that, without this, would have
/// been a no-op scope-end rather than an actual zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey<E: Pairing> {
    pub delta: E::ScalarField,
}

/// Publishable evidence that a contribution was performed correctly,
/// without revealing `delta`. Checked by [`crate::params::verify_transcript`].
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey<E: Pairing> {
    /// `delta_g1` after this contribution's scaling.
    pub delta_after: E::G1Affine,
    /// Random `G1` element chosen fresh for this contribution.
    pub s: E::G1Affine,
    /// `s` scaled by this contribution's secret delta.
    pub s_delta: E::G1Affine,
    /// `hash_to_g2(transcript)`, scaled by delta — the actual
    /// "signature of knowledge" of delta, without revealing it.
    pub r_delta: E::G2Affine,
    /// `H(cs_hash || <every prior contribution> || s || s_delta)`. Binds
    /// this contribution to its exact position in the chain; recomputed
    /// independently during verification, never trusted from the
    /// contributor.
    pub transcript: [u8; 64],
}

impl<E: Pairing> PublicKey<E> {
    /// Canonical byte encoding, used both for hashing (`hash_cs_pubkeys`,
    /// `hash`) and for persisting a contribution alongside the
    /// parameters it produced.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.delta_after
            .serialize_compressed(&mut bytes)
            .expect("serializing a well-formed curve point cannot fail");
        self.s
            .serialize_compressed(&mut bytes)
            .expect("serializing a well-formed curve point cannot fail");
        self.s_delta
            .serialize_compressed(&mut bytes)
            .expect("serializing a well-formed curve point cannot fail");
        self.r_delta
            .serialize_compressed(&mut bytes)
            .expect("serializing a well-formed curve point cannot fail");
        bytes.extend_from_slice(&self.transcript);
        bytes
    }

    /// Blake2b-512 hash of this public key's canonical encoding — the
    /// value a contributor can independently check appears in
    /// [`crate::params::MPCParameters::verify`]'s output, to confirm
    /// their contribution actually made it into the chain.
    pub fn hash(&self) -> [u8; 64] {
        let mut hasher = Blake2b512::new();
        hasher.update(self.to_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&digest);
        out
    }
}

pub struct Keypair<E: Pairing> {
    pub private_key: PrivateKey<E>,
    pub public_key: PublicKey<E>,
}

impl<E: Pairing> Keypair<E> {
    /// Computes one contributor's keypair for this step of the ceremony.
    ///
    /// - `delta_g1`: the *current* `delta_g1` from the parameters being
    ///   contributed to, i.e. before this contribution is applied.
    /// - `cs_hash`: the ceremony's fixed circuit fingerprint (see
    ///   `proof-of-observation`'s `fingerprint` binary) — every
    ///   contributor must be contributing to the exact same circuit.
    /// - `contributions`: every prior accepted contribution, in order.
    ///
    /// Callers MUST discard `private_key.delta` as soon as it's been
    /// consumed by [`crate::params::MPCParameters::contribute`] — see
    /// `docs/CEREMONY.md`.
    pub fn new(
        delta_g1: E::G1Affine,
        cs_hash: [u8; 64],
        contributions: &[PublicKey<E>],
        rng: &mut impl Rng,
    ) -> Self {
        // THE toxic waste.
        let delta = E::ScalarField::rand(rng);
        let delta_after = (delta_g1 * delta).into_affine();

        let s = E::G1::rand(rng).into_affine();
        let s_delta = (s * delta).into_affine();

        let transcript = hash_cs_pubkeys::<E>(cs_hash, contributions, s, s_delta);
        let r = hash_to_g2::<E>(&transcript).into_affine();
        let r_delta = (r * delta).into_affine();

        Self {
            public_key: PublicKey {
                delta_after,
                s,
                s_delta,
                r_delta,
                transcript,
            },
            private_key: PrivateKey { delta },
        }
    }
}

/// `H(cs_hash || <every prior contribution> || s || s_delta)`, Blake2b-512.
/// See the module-level docs for the one deliberate departure from the
/// reference implementation's exact byte format here.
pub fn hash_cs_pubkeys<E: Pairing>(
    cs_hash: [u8; 64],
    contributions: &[PublicKey<E>],
    s: E::G1Affine,
    s_delta: E::G1Affine,
) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(cs_hash);
    for pubkey in contributions {
        hasher.update(pubkey.to_bytes());
    }
    let mut s_bytes = Vec::new();
    s.serialize_compressed(&mut s_bytes)
        .expect("serializing a well-formed curve point cannot fail");
    let mut s_delta_bytes = Vec::new();
    s_delta
        .serialize_compressed(&mut s_delta_bytes)
        .expect("serializing a well-formed curve point cannot fail");
    hasher.update(&s_bytes);
    hasher.update(&s_delta_bytes);

    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, G1Affine};
    use ark_ec::AffineRepr;
    use rand::thread_rng;

    #[test]
    fn keypair_generation_is_internally_consistent() {
        let mut rng = thread_rng();
        let delta_g1 = G1Affine::generator();
        let kp = Keypair::<Bn254>::new(delta_g1, [0u8; 64], &[], &mut rng);

        // delta_after must equal delta_g1 scaled by the private delta.
        assert_eq!(
            kp.public_key.delta_after,
            (delta_g1 * kp.private_key.delta).into_affine()
        );
        // s_delta must equal s scaled by the same private delta.
        assert_eq!(
            kp.public_key.s_delta,
            (kp.public_key.s * kp.private_key.delta).into_affine()
        );
    }

    #[test]
    fn two_contributions_get_different_secrets() {
        let mut rng = thread_rng();
        let delta_g1 = G1Affine::generator();
        let kp1 = Keypair::<Bn254>::new(delta_g1, [0u8; 64], &[], &mut rng);
        let kp2 = Keypair::<Bn254>::new(delta_g1, [0u8; 64], &[], &mut rng);
        assert_ne!(kp1.private_key.delta, kp2.private_key.delta);
    }

    #[test]
    fn hash_cs_pubkeys_changes_with_prior_contributions() {
        let mut rng = thread_rng();
        let delta_g1 = G1Affine::generator();
        let kp1 = Keypair::<Bn254>::new(delta_g1, [0u8; 64], &[], &mut rng);

        let s = kp1.public_key.s;
        let s_delta = kp1.public_key.s_delta;
        let empty_hash = hash_cs_pubkeys::<Bn254>([0u8; 64], &[], s, s_delta);
        let with_prior = hash_cs_pubkeys::<Bn254>([0u8; 64], &[kp1.public_key.clone()], s, s_delta);
        assert_ne!(
            empty_hash, with_prior,
            "the transcript must depend on prior contributions, to prevent chain reordering"
        );
    }
}
