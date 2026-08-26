//! Ported from celo-org/snark-setup (a fork of kobigurk/phase2-bn254,
//! itself the reference BGM17 Phase 2 implementation used by Tornado
//! Cash, Semaphore, and others), `setup-utils/src/helpers.rs`, to modern
//! arkworks 0.4 (`ark_ec::pairing::Pairing` in place of the pre-rename
//! `algebra::PairingEngine`). Checked line-for-line against that source
//! before writing this — not reconstructed from memory or a general
//! description of BGM17. Not independently audited; see
//! `docs/CEREMONY.md`.

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, Zero};
use rand::{thread_rng, RngCore};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;

/// Hashes an arbitrary digest to a uniformly random point in `E::G2`,
/// whose discrete log is not efficiently known to anyone — this is the
/// "hash to group" step the entire signature-of-knowledge construction
/// depends on. Uses the reference implementation's exact approach:
/// ChaCha20, seeded from the first 32 bytes of `digest`, rejection-samples
/// uniformly random bytes until they decode to a valid curve point via
/// `from_random_bytes`, then clears the cofactor to land in the correct
/// prime-order subgroup, retrying on the (astronomically unlikely) zero
/// result.
///
/// # Panics
/// If `digest` is shorter than 32 bytes.
pub fn hash_to_g2<E: Pairing>(digest: &[u8]) -> E::G2 {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    let mut rng = ChaChaRng::from_seed(seed);
    loop {
        let mut bytes = vec![0u8; E::G2Affine::generator().uncompressed_size()];
        rng.fill_bytes(&mut bytes);
        if let Some(p) = E::G2Affine::from_random_bytes(&bytes) {
            let scaled = p.mul_by_cofactor_to_group();
            if !scaled.into_affine().is_zero() {
                return scaled;
            }
        }
    }
}

/// Checks `g1.0 / g1.1 == g2.0 / g2.1` (as an implicit ratio in the
/// respective groups) via the pairing equality `e(g1.0, g2.1) ==
/// e(g1.1, g2.0)`. This is the single check that lets a verifier confirm
/// two group elements were scaled by the *same* secret scalar without
/// ever learning that scalar — every invariant `MPCParameters::verify`
/// checks ultimately reduces to one or more calls to this.
pub fn same_ratio<E: Pairing>(
    g1: &(E::G1Affine, E::G1Affine),
    g2: &(E::G2Affine, E::G2Affine),
) -> bool {
    E::pairing(g1.0, g2.1) == E::pairing(g1.1, g2.0)
}

#[derive(Debug)]
pub struct RatioMismatch(pub &'static str);

impl std::fmt::Display for RatioMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ratio check failed: {}", self.0)
    }
}
impl std::error::Error for RatioMismatch {}

pub fn check_same_ratio<E: Pairing>(
    g1: &(E::G1Affine, E::G1Affine),
    g2: &(E::G2Affine, E::G2Affine),
    err: &'static str,
) -> Result<(), RatioMismatch> {
    if g1.0.is_zero() || g1.1.is_zero() || g2.0.is_zero() || g2.1.is_zero() {
        return Err(RatioMismatch(err));
    }
    if !same_ratio::<E>(g1, g2) {
        return Err(RatioMismatch(err));
    }
    Ok(())
}

/// Combines two equal-length vectors of curve points into a single pair,
/// via a random linear combination, so that checking "every element of
/// `v1` relates to the corresponding element of `v2` by the same ratio"
/// reduces to *one* pairing check instead of `v1.len()` of them. Sound
/// because a cheating prover who got even one element wrong would need to
/// predict the verifier's random combination coefficients in advance to
/// have the errors cancel out — negligible probability.
pub fn merge_pairs<G: AffineRepr>(v1: &[G], v2: &[G]) -> (G, G) {
    assert_eq!(v1.len(), v2.len(), "merge_pairs: mismatched lengths");
    let rng = &mut thread_rng();

    let mut acc1 = G::Group::zero();
    let mut acc2 = G::Group::zero();
    for (a, b) in v1.iter().zip(v2.iter()) {
        let r = G::ScalarField::rand(rng);
        let r_repr = r.into_bigint();
        acc1 += a.mul_bigint(r_repr);
        acc2 += b.mul_bigint(r_repr);
    }
    (acc1.into_affine(), acc2.into_affine())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};

    #[test]
    fn hash_to_g2_is_deterministic() {
        let d = [7u8; 40];
        assert_eq!(hash_to_g2::<Bn254>(&d), hash_to_g2::<Bn254>(&d));
    }

    #[test]
    fn hash_to_g2_differs_for_different_digests() {
        // hash_to_g2 is documented (matching the reference) to only use
        // the first 32 bytes of the digest — differ within that range,
        // not just anywhere in a longer digest.
        let mut d1 = [7u8; 40];
        let d2 = [7u8; 40];
        d1[0] = 8;
        assert_ne!(hash_to_g2::<Bn254>(&d1), hash_to_g2::<Bn254>(&d2));
    }

    #[test]
    fn hash_to_g2_ignores_bytes_beyond_the_first_32() {
        // Documents the "first 32 bytes only" behavior explicitly, rather
        // than leaving it as an easy-to-violate assumption future callers
        // might not realize.
        let mut d1 = [7u8; 40];
        let d2 = [7u8; 40];
        d1[39] = 8;
        assert_eq!(hash_to_g2::<Bn254>(&d1), hash_to_g2::<Bn254>(&d2));
    }

    #[test]
    fn same_ratio_accepts_consistent_scaling() {
        let mut rng = thread_rng();
        let s = Fr::rand(&mut rng);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let g1_s = (g1 * s).into_affine();
        let g2_s = (g2 * s).into_affine();
        assert!(same_ratio::<Bn254>(&(g1, g1_s), &(g2, g2_s)));
    }

    #[test]
    fn same_ratio_rejects_mismatched_scaling() {
        let mut rng = thread_rng();
        let s = Fr::rand(&mut rng);
        let wrong_s = Fr::rand(&mut rng);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let g1_s = (g1 * s).into_affine();
        let g2_wrong = (g2 * wrong_s).into_affine();
        assert!(!same_ratio::<Bn254>(&(g1, g1_s), &(g2, g2_wrong)));
    }

    #[test]
    fn merge_pairs_catches_a_single_tampered_element() {
        let mut rng = thread_rng();
        let s = Fr::rand(&mut rng);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let v1: Vec<G1Affine> = (0..5)
            .map(|_| (g1 * Fr::rand(&mut rng)).into_affine())
            .collect();
        let v2: Vec<G1Affine> = v1.iter().map(|p| (*p * s).into_affine()).collect();

        let (a, b) = merge_pairs(&v1, &v2);
        assert!(
            check_same_ratio::<Bn254>(&(a, b), &(g2, (g2 * s).into_affine()), "should pass")
                .is_ok()
        );

        // tamper with one element of v2
        let mut v2_bad = v2.clone();
        v2_bad[2] = (v2_bad[2] * Fr::rand(&mut rng)).into_affine();
        let (a2, b2) = merge_pairs(&v1, &v2_bad);
        assert!(
            check_same_ratio::<Bn254>(&(a2, b2), &(g2, (g2 * s).into_affine()), "should fail")
                .is_err()
        );
    }
}
