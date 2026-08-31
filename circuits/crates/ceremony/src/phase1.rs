//! Phase 1 ("Powers of Tau") — the circuit-*independent* half of a Groth16
//! trusted setup. Produces a universal structured reference string, reused
//! as-is across any circuit up to a size bound fixed at initialization.
//!
//! Ported from celo-org/snark-setup's `phase1` crate (`key_generation.rs`,
//! `computation.rs`, `verification.rs`), checked against that source
//! before writing this, to modern arkworks 0.4. Deliberately NOT ported:
//! the chunked/memory-mapped streaming machinery that lets a real-world
//! ceremony handle accumulators with millions of elements — this
//! implementation holds everything in memory, which is fine for the
//! modest sizes `proof-of-observation` needs (thousands of elements, not
//! millions) and considerably simpler to have gotten right.
//!
//! Not independently audited; see `docs/CEREMONY.md`.

use crate::helpers::{check_same_ratio, compute_g2_s, power_pairs, RatioMismatch};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use blake2::{Blake2b512, Digest};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The universal (circuit-independent) reference string this ceremony
/// produces. `tau_powers_g1` needs roughly twice the length of the
/// others — see [`Accumulator::new`] for why.
#[derive(Clone, Debug, PartialEq)]
pub struct Accumulator<E: Pairing> {
    pub tau_powers_g1: Vec<E::G1Affine>,
    pub tau_powers_g2: Vec<E::G2Affine>,
    pub alpha_tau_powers_g1: Vec<E::G1Affine>,
    pub beta_tau_powers_g1: Vec<E::G1Affine>,
    pub beta_g2: E::G2Affine,
}

impl<E: Pairing> Accumulator<E> {
    /// Builds the starting point: every element is the plain curve
    /// generator, i.e. `tau = alpha = beta = 1` implicitly — the same
    /// "start at the identity scalar" convention Phase 2's delta begins
    /// from. `size` must be at least the circuit's QAP domain size (see
    /// `docs/CEREMONY.md` on choosing this deliberately, not by inertia).
    /// `tau_powers_g1` gets `2 * size - 1` elements (needed for the
    /// H-query construction downstream), the rest get `size`.
    pub fn new(size: usize) -> Self {
        let g1 = E::G1Affine::generator();
        let g2 = E::G2Affine::generator();
        Self {
            tau_powers_g1: vec![g1; 2 * size - 1],
            tau_powers_g2: vec![g2; size],
            alpha_tau_powers_g1: vec![g1; size],
            beta_tau_powers_g1: vec![g1; size],
            beta_g2: g2,
        }
    }

    pub fn hash(&self) -> [u8; 64] {
        let mut bytes = Vec::new();
        for p in &self.tau_powers_g1 {
            p.serialize_compressed(&mut bytes).expect("infallible");
        }
        for p in &self.tau_powers_g2 {
            p.serialize_compressed(&mut bytes).expect("infallible");
        }
        for p in &self.alpha_tau_powers_g1 {
            p.serialize_compressed(&mut bytes).expect("infallible");
        }
        for p in &self.beta_tau_powers_g1 {
            p.serialize_compressed(&mut bytes).expect("infallible");
        }
        self.beta_g2
            .serialize_compressed(&mut bytes)
            .expect("infallible");

        let mut hasher = Blake2b512::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&digest);
        out
    }
}

/// The three secrets (tau, alpha, beta) one contributor destroys after
/// contributing. `Zeroize`d on drop, matching this crate's Phase 2
/// `PrivateKey` and the rest of this workspace's care with secrets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey<E: Pairing> {
    pub tau: E::ScalarField,
    pub alpha: E::ScalarField,
    pub beta: E::ScalarField,
}

/// One (G1, G1) pair plus the G2 element scaled by the same secret — the
/// same BGM17 signature-of-knowledge shape Phase 2 uses for `delta`,
/// applied here three times (once each for tau/alpha/beta).
#[derive(Clone, Debug, PartialEq)]
pub struct SecretProof<E: Pairing> {
    pub g1_s: E::G1Affine,
    pub g1_s_x: E::G1Affine,
    pub g2_s_x: E::G2Affine,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey<E: Pairing> {
    pub tau: SecretProof<E>,
    pub alpha: SecretProof<E>,
    pub beta: SecretProof<E>,
}

impl<E: Pairing> PublicKey<E> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for proof in [&self.tau, &self.alpha, &self.beta] {
            proof
                .g1_s
                .serialize_compressed(&mut bytes)
                .expect("infallible");
            proof
                .g1_s_x
                .serialize_compressed(&mut bytes)
                .expect("infallible");
            proof
                .g2_s_x
                .serialize_compressed(&mut bytes)
                .expect("infallible");
        }
        bytes
    }

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

/// Personalization tags distinguishing tau/alpha/beta's hash-to-G2 calls
/// from each other, matching the reference exactly — without these, the
/// three secrets' signatures would be interchangeable.
const TAU_PERSONALIZATION: u8 = 0;
const ALPHA_PERSONALIZATION: u8 = 1;
const BETA_PERSONALIZATION: u8 = 2;

fn prove_secret<E: Pairing>(
    secret: E::ScalarField,
    personalization: u8,
    digest: &[u8],
    rng: &mut impl Rng,
) -> SecretProof<E> {
    let g1_s = E::G1::rand(rng).into_affine();
    let g1_s_x = (g1_s * secret).into_affine();
    let g2_s = compute_g2_s::<E>(digest, g1_s, g1_s_x, personalization);
    let g2_s_x = (g2_s * secret).into_affine();
    SecretProof {
        g1_s,
        g1_s_x,
        g2_s_x,
    }
}

impl<E: Pairing> Keypair<E> {
    /// `digest` must be the hash of the *previous* accumulator state
    /// (`Accumulator::hash`) — this is what binds a contribution to its
    /// exact position in the chain, exactly as Phase 2's transcript
    /// chaining does with `hash_cs_pubkeys`, just using the accumulator's
    /// own bytes directly as the thing being hashed instead of a running
    /// chain hash.
    pub fn new(digest: &[u8], rng: &mut impl Rng) -> Self {
        let tau = E::ScalarField::rand(rng);
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);

        let tau_proof = prove_secret::<E>(tau, TAU_PERSONALIZATION, digest, rng);
        let alpha_proof = prove_secret::<E>(alpha, ALPHA_PERSONALIZATION, digest, rng);
        let beta_proof = prove_secret::<E>(beta, BETA_PERSONALIZATION, digest, rng);

        Self {
            private_key: PrivateKey { tau, alpha, beta },
            public_key: PublicKey {
                tau: tau_proof,
                alpha: alpha_proof,
                beta: beta_proof,
            },
        }
    }
}

/// Applies one contribution to an accumulator, consuming (and, via
/// `PrivateKey`'s `Zeroize`, destroying) the fresh randomness. Returns
/// the new accumulator and the public key to publish alongside it.
pub fn contribute<E: Pairing>(
    before: &Accumulator<E>,
    rng: &mut impl Rng,
) -> (Accumulator<E>, PublicKey<E>) {
    let digest = before.hash();
    let Keypair {
        private_key,
        public_key,
    } = Keypair::new(&digest, rng);

    let size = before.tau_powers_g2.len();
    let mut tau_powers_g1 = Vec::with_capacity(before.tau_powers_g1.len());
    let mut tau_power = E::ScalarField::from(1u64);
    for p in &before.tau_powers_g1 {
        tau_powers_g1.push((*p * tau_power).into_affine());
        tau_power *= private_key.tau;
    }

    let mut tau_powers_g2 = Vec::with_capacity(size);
    let mut alpha_tau_powers_g1 = Vec::with_capacity(size);
    let mut beta_tau_powers_g1 = Vec::with_capacity(size);
    let mut tau_power = E::ScalarField::from(1u64);
    for i in 0..size {
        tau_powers_g2.push((before.tau_powers_g2[i] * tau_power).into_affine());
        let alpha_scalar: E::ScalarField = private_key.alpha * tau_power;
        alpha_tau_powers_g1.push((before.alpha_tau_powers_g1[i] * alpha_scalar).into_affine());
        let beta_scalar: E::ScalarField = private_key.beta * tau_power;
        beta_tau_powers_g1.push((before.beta_tau_powers_g1[i] * beta_scalar).into_affine());
        tau_power *= private_key.tau;
    }

    let beta_g2: E::G2 = before.beta_g2 * private_key.beta;
    let beta_g2 = beta_g2.into_affine();

    // private_key (and its tau/alpha/beta) is dropped here.
    drop(private_key);

    (
        Accumulator {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2,
        },
        public_key,
    )
}

/// Verifies one hop: that `after` is a valid evolution of `before` by
/// exactly the contribution `pubkey` claims. Mirrors the reference's
/// `verification.rs` invariant checks: each secret's own signature of
/// knowledge, that the claimed per-secret delta between `before`/`after`
/// matches that signature, and — separately — that `after`'s own
/// sequences are genuinely geometric progressions (not just that the
/// *first* couple of elements look right).
pub fn verify<E: Pairing>(
    before: &Accumulator<E>,
    after: &Accumulator<E>,
    pubkey: &PublicKey<E>,
) -> Result<(), RatioMismatch> {
    let digest = before.hash();

    // Recompute each secret's g2_s ONCE, reused both for its own
    // proof-of-knowledge check and for the before/after delta check below
    // — matching the reference's `compute_g2_s_key`, which does the same.
    let tau_g2_s = compute_g2_s::<E>(
        &digest,
        pubkey.tau.g1_s,
        pubkey.tau.g1_s_x,
        TAU_PERSONALIZATION,
    )
    .into_affine();
    let alpha_g2_s = compute_g2_s::<E>(
        &digest,
        pubkey.alpha.g1_s,
        pubkey.alpha.g1_s_x,
        ALPHA_PERSONALIZATION,
    )
    .into_affine();
    let beta_g2_s = compute_g2_s::<E>(
        &digest,
        pubkey.beta.g1_s,
        pubkey.beta.g1_s_x,
        BETA_PERSONALIZATION,
    )
    .into_affine();

    // Proofs of knowledge for tau, alpha, beta.
    check_same_ratio::<E>(
        &(pubkey.tau.g1_s, pubkey.tau.g1_s_x),
        &(tau_g2_s, pubkey.tau.g2_s_x),
        "tau G1<>G2",
    )?;
    check_same_ratio::<E>(
        &(pubkey.alpha.g1_s, pubkey.alpha.g1_s_x),
        &(alpha_g2_s, pubkey.alpha.g2_s_x),
        "alpha G1<>G2",
    )?;
    check_same_ratio::<E>(
        &(pubkey.beta.g1_s, pubkey.beta.g1_s_x),
        &(beta_g2_s, pubkey.beta.g2_s_x),
        "beta G1<>G2",
    )?;

    // tau_powers_g1[0] / tau_powers_g2[0] never change: tau^0 = 1 always.
    if after.tau_powers_g1[0] != E::G1Affine::generator() {
        return Err(RatioMismatch(
            "tau_powers_g1[0] must always be the fixed generator",
        ));
    }
    if after.tau_powers_g2[0] != E::G2Affine::generator() {
        return Err(RatioMismatch(
            "tau_powers_g2[0] must always be the fixed generator",
        ));
    }

    // tau^1 was multiplied correctly, checked from both the G1 and G2 side.
    check_same_ratio::<E>(
        &(before.tau_powers_g1[1], after.tau_powers_g1[1]),
        &(tau_g2_s, pubkey.tau.g2_s_x),
        "before/after tau_g1[1]",
    )?;
    check_same_ratio::<E>(
        &(pubkey.tau.g1_s, pubkey.tau.g1_s_x),
        &(before.tau_powers_g2[1], after.tau_powers_g2[1]),
        "before/after tau_g2[1]",
    )?;

    // alpha_tau_powers_g1[0] / beta_tau_powers_g1[0] were multiplied
    // correctly (these equal plain alpha*G1 / beta*G1, since tau^0 = 1).
    check_same_ratio::<E>(
        &(before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]),
        &(alpha_g2_s, pubkey.alpha.g2_s_x),
        "before/after alpha_tau_powers_g1[0]",
    )?;
    check_same_ratio::<E>(
        &(before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
        &(beta_g2_s, pubkey.beta.g2_s_x),
        "before/after beta_tau_powers_g1[0]",
    )?;

    // beta_g2 was multiplied correctly.
    check_same_ratio::<E>(
        &(pubkey.beta.g1_s, pubkey.beta.g1_s_x),
        &(before.beta_g2, after.beta_g2),
        "before/after beta_g2",
    )?;

    // Whole-sequence self-consistency: confirm after's own tau_powers_g1/g2
    // form a genuine geometric progression — not merely that the first
    // couple of elements look right (a cheating contributor could
    // otherwise tamper with a later element freely). The reference keeps
    // this as a separate "aggregate_verification" pass run once on the
    // final output; this implementation runs it on every hop instead,
    // which is strictly stronger (catches tampering immediately rather
    // than only at final acceptance) at a modest extra cost, acceptable
    // at our in-memory circuit size.
    let g1_check = power_pairs(&after.tau_powers_g1);
    check_same_ratio::<E>(
        &g1_check,
        &(after.tau_powers_g2[0], after.tau_powers_g2[1]),
        "tau_powers_g1 is not a geometric sequence",
    )?;
    let g2_check = power_pairs(&after.tau_powers_g2);
    check_same_ratio::<E>(
        &(after.tau_powers_g1[0], after.tau_powers_g1[1]),
        &g2_check,
        "tau_powers_g2 is not a geometric sequence",
    )?;

    let alpha_check = power_pairs(&after.alpha_tau_powers_g1);
    check_same_ratio::<E>(
        &alpha_check,
        &(after.tau_powers_g2[0], after.tau_powers_g2[1]),
        "alpha_tau_powers_g1 is not a consistent geometric sequence",
    )?;
    let beta_check = power_pairs(&after.beta_tau_powers_g1);
    check_same_ratio::<E>(
        &beta_check,
        &(after.tau_powers_g2[0], after.tau_powers_g2[1]),
        "beta_tau_powers_g1 is not a consistent geometric sequence",
    )?;

    Ok(())
}

// re-export for callers that want to batch-check a whole chain the way
// `verify_transcript` does for Phase 2 — kept simple (loop + verify) since
// Phase 1's `verify` is already a single, self-contained hop check, unlike
// Phase 2's chain-position-binding transcript.
pub fn verify_chain<E: Pairing>(
    states: &[Accumulator<E>],
    pubkeys: &[PublicKey<E>],
) -> Result<(), RatioMismatch> {
    assert_eq!(
        states.len(),
        pubkeys.len() + 1,
        "need exactly one more state than contributions"
    );
    for i in 0..pubkeys.len() {
        verify::<E>(&states[i], &states[i + 1], &pubkeys[i])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use rand::thread_rng;

    #[test]
    fn single_contribution_verifies() {
        let mut rng = thread_rng();
        let before = Accumulator::<Bn254>::new(4);
        let (after, pubkey) = contribute(&before, &mut rng);
        verify(&before, &after, &pubkey).expect("an honest contribution must verify");
    }

    #[test]
    fn three_contributions_chain_verifies() {
        let mut rng = thread_rng();
        let mut states = vec![Accumulator::<Bn254>::new(4)];
        let mut pubkeys = vec![];
        for _ in 0..3 {
            let (after, pubkey) = contribute(states.last().unwrap(), &mut rng);
            states.push(after);
            pubkeys.push(pubkey);
        }
        verify_chain(&states, &pubkeys).expect("a valid 3-contribution chain must verify");
    }

    #[test]
    fn tampered_element_is_rejected() {
        let mut rng = thread_rng();
        let before = Accumulator::<Bn254>::new(4);
        let (mut after, pubkey) = contribute(&before, &mut rng);
        // Tamper with an element NOT covered by the index-0/index-1
        // single-step checks, to specifically exercise the
        // whole-sequence geometric-progression check.
        after.tau_powers_g1[3] = (after.tau_powers_g1[3] * ark_bn254::Fr::from(2u64)).into_affine();
        let result = verify(&before, &after, &pubkey);
        assert!(
            result.is_err(),
            "tampering with a later element must be caught by the sequence check"
        );
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let mut rng = thread_rng();
        let before = Accumulator::<Bn254>::new(4);
        let (after, _pubkey) = contribute(&before, &mut rng);
        // A public key from an unrelated contribution to the same
        // starting accumulator must not verify against this `after`.
        let (_, wrong_pubkey) = contribute(&before, &mut rng);
        let result = verify(&before, &after, &wrong_pubkey);
        assert!(result.is_err());
    }
}
