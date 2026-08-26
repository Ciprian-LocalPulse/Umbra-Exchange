//! Ported from celo-org/snark-setup's `phase2/src/parameters.rs`
//! (`MPCParameters::contribute`/`verify`/`verify_transcript`) to modern
//! arkworks 0.4. Checked line-for-line against that source before writing
//! this. Not independently audited; see `docs/CEREMONY.md`.
//!
//! # What this deliberately does NOT do
//!
//! The reference builds its *starting* (pre-contribution) parameters from
//! raw Powers-of-Tau accumulator output via an FFT-based Lagrange
//! evaluation (`phase2::parameters::eval`, consuming `phase1`'s
//! accumulator) — i.e. real Phase 1 ceremony output. This module does not
//! implement that ingestion step; `MPCParameters::new_placeholder` below
//! builds a starting point directly via
//! `Groth16::generate_parameters_with_qap` with `alpha`/`beta`/`gamma`
//! chosen locally (NOT from a real Phase 1 ceremony — same "local,
//! non-ceremony, toxic waste not destroyed by anyone but you" caveat as
//! `umbra-relay-keygen`) and `delta` fixed to `1`, which is the exact
//! algebraic starting state a real ceremony's Phase 2 also begins from
//! (see the reference: `delta_g1`/`delta_g2` both start as the bare
//! generator, before any contributor has multiplied by their secret).
//!
//! What IS real here, faithfully ported and tested: the `contribute` and
//! `verify` logic that re-randomizes `delta` and produces/checks the
//! pairing-based signature of knowledge — the part whose soundness this
//! whole ceremony actually rests on, once a trustworthy starting point
//! exists.

use crate::helpers::{check_same_ratio, merge_pairs};
use crate::keypair::{hash_cs_pubkeys, Keypair, PublicKey};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use blake2::{Blake2b512, Digest};
use rand::Rng;
use std::fmt;

#[derive(Debug)]
pub enum CeremonyError {
    NoContributions,
    InvalidLength,
    BrokenInvariant(&'static str),
    Ratio(&'static str),
    Serialization(String),
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CeremonyError::NoContributions => write!(f, "no contributions found"),
            CeremonyError::InvalidLength => write!(f, "query length mismatch between before/after"),
            CeremonyError::BrokenInvariant(what) => write!(
                f,
                "broken invariant: {what} must not change between contributions"
            ),
            CeremonyError::Ratio(what) => write!(f, "ratio check failed: {what}"),
            CeremonyError::Serialization(e) => write!(f, "serialization error: {e}"),
        }
    }
}
impl std::error::Error for CeremonyError {}

type Result<T> = std::result::Result<T, CeremonyError>;

fn ensure_unchanged<T: PartialEq>(before: T, after: T, what: &'static str) -> Result<()> {
    if before != after {
        return Err(CeremonyError::BrokenInvariant(what));
    }
    Ok(())
}

fn ensure_same_length<T, U>(a: &[T], b: &[U]) -> Result<()> {
    if a.len() != b.len() {
        return Err(CeremonyError::InvalidLength);
    }
    Ok(())
}

/// Parameters for one circuit, plus a verifiable transcript of every
/// contribution applied so far. Mirrors the reference's `MPCParameters<E>`.
#[derive(Clone)]
pub struct MPCParameters<E: Pairing> {
    pub params: ProvingKey<E>,
    /// Fixes which circuit this ceremony is for — every participant must
    /// confirm they get the same value before contributing (see
    /// `proof-of-observation`'s `fingerprint` binary and
    /// `docs/CEREMONY.md`).
    pub cs_hash: [u8; 64],
    pub contributions: Vec<PublicKey<E>>,
}

impl<E: Pairing> MPCParameters<E> {
    /// Builds a starting point for a ceremony directly, WITHOUT consuming
    /// real Phase 1 output — see module docs for exactly what this does
    /// and doesn't provide soundness for. Only `delta` is fixed to `1`
    /// (correct and required for the ceremony math below to be
    /// meaningful); `alpha`/`beta`/`gamma`/the two generators are sampled
    /// locally, which is NOT a substitute for real Phase 1 randomness.
    pub fn new_placeholder<C, R: Rng>(circuit: C, rng: &mut R) -> Result<Self>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        let gamma = E::ScalarField::rand(rng);
        let delta = E::ScalarField::ONE;
        // MUST be the curve's actual, fixed, universally-known generator
        // — not a random point. The whole signature-of-knowledge scheme
        // in `verify`/`verify_transcript` (ported faithfully from the
        // reference) checks contributions against
        // `E::G1Affine::generator()`/`E::G2Affine::generator()`
        // specifically; using anything else here would silently produce
        // parameters that fail every subsequent verification. Confirmed
        // against the reference source before fixing this (it also
        // always uses `prime_subgroup_generator()`, arkworks 0.3's name
        // for the same thing 0.4 calls `generator()`) — caught by
        // `full_ceremony_chain_produces_a_working_keypair` failing with
        // "inconsistent G2 delta" when this used `E::G1::rand(rng)`.
        let g1_generator = E::G1::generator();
        let g2_generator = E::G2::generator();

        let params = Groth16::<E>::generate_parameters_with_qap(
            circuit,
            alpha,
            beta,
            gamma,
            delta,
            g1_generator,
            g2_generator,
            rng,
        )
        .map_err(|e: SynthesisError| CeremonyError::Serialization(e.to_string()))?;

        let cs_hash = hash_params(&params)?;

        Ok(Self {
            params,
            cs_hash,
            contributions: vec![],
        })
    }

    /// Contributes fresh randomness, re-randomizing `delta`. Only one
    /// contributor across a ceremony's whole history needs to honestly
    /// destroy their secret for the final parameters to be sound.
    /// Returns the contribution's hash, so the contributor can later
    /// confirm it's present in the output of [`Self::verify`].
    pub fn contribute<R: Rng>(&mut self, rng: &mut R) -> Result<[u8; 64]> {
        let Keypair {
            public_key,
            private_key,
        } = Keypair::new(self.params.delta_g1, self.cs_hash, &self.contributions, rng);

        let delta_inv = private_key
            .delta
            .inverse()
            .expect("a uniformly random field element is nonzero with overwhelming probability");

        for l in self.params.l_query.iter_mut() {
            *l = (*l * delta_inv).into_affine();
        }
        for h in self.params.h_query.iter_mut() {
            *h = (*h * delta_inv).into_affine();
        }
        self.params.vk.delta_g2 = (self.params.vk.delta_g2 * private_key.delta).into_affine();
        self.params.delta_g1 = (self.params.delta_g1 * private_key.delta).into_affine();

        // private_key (and its `delta`) is dropped here — this is the
        // toxic waste; nothing beyond this point in this function's scope
        // retains it.
        drop(private_key);

        self.contributions.push(public_key.clone());
        Ok(public_key.hash())
    }

    /// Verifies that `after` is a valid evolution of `self` by exactly
    /// one additional contribution (the last one in `after.contributions`),
    /// checking every invariant the reference implementation checks:
    /// which fields must stay byte-identical, which must change only via
    /// the claimed delta, and that the claimed contribution's signature
    /// of knowledge is valid. Returns the hash of every contribution in
    /// `after`'s history on success, so a contributor can confirm their
    /// own contribution's hash is present.
    pub fn verify(&self, after: &Self) -> Result<Vec<[u8; 64]>> {
        let before = self;
        let pubkey = after
            .contributions
            .last()
            .ok_or(CeremonyError::NoContributions)?;

        ensure_unchanged(pubkey.delta_after, after.params.delta_g1, "delta_g1")?;
        check_same_ratio::<E>(
            &(E::G1Affine::generator(), pubkey.delta_after),
            &(E::G2Affine::generator(), after.params.vk.delta_g2),
            "inconsistent G2 delta",
        )
        .map_err(|e| CeremonyError::Ratio(leak(e.0)))?;

        ensure_unchanged(
            &before.contributions[..],
            &after.contributions[..before.contributions.len()],
            "prior contributions",
        )?;
        ensure_unchanged(&before.cs_hash[..], &after.cs_hash[..], "cs_hash")?;

        ensure_same_length(&before.params.h_query, &after.params.h_query)?;
        ensure_same_length(&before.params.l_query, &after.params.l_query)?;

        ensure_unchanged(
            before.params.vk.alpha_g1,
            after.params.vk.alpha_g1,
            "alpha_g1",
        )?;
        ensure_unchanged(before.params.beta_g1, after.params.beta_g1, "beta_g1")?;
        ensure_unchanged(before.params.vk.beta_g2, after.params.vk.beta_g2, "beta_g2")?;
        ensure_unchanged(
            before.params.vk.gamma_g2,
            after.params.vk.gamma_g2,
            "gamma_g2",
        )?;
        if before.params.vk.gamma_abc_g1 != after.params.vk.gamma_abc_g1 {
            return Err(CeremonyError::BrokenInvariant("gamma_abc_g1"));
        }
        if before.params.a_query != after.params.a_query {
            return Err(CeremonyError::BrokenInvariant("a_query"));
        }
        if before.params.b_g1_query != after.params.b_g1_query {
            return Err(CeremonyError::BrokenInvariant("b_g1_query"));
        }
        if before.params.b_g2_query != after.params.b_g2_query {
            return Err(CeremonyError::BrokenInvariant("b_g2_query"));
        }

        if !before.params.h_query.is_empty() {
            let pair = merge_pairs(&before.params.h_query, &after.params.h_query);
            check_same_ratio::<E>(
                &pair,
                &(after.params.vk.delta_g2, before.params.vk.delta_g2),
                "H_query ratio",
            )
            .map_err(|e| CeremonyError::Ratio(leak(e.0)))?;
        }
        if !before.params.l_query.is_empty() {
            let pair = merge_pairs(&before.params.l_query, &after.params.l_query);
            check_same_ratio::<E>(
                &pair,
                &(after.params.vk.delta_g2, before.params.vk.delta_g2),
                "L_query ratio",
            )
            .map_err(|e| CeremonyError::Ratio(leak(e.0)))?;
        }

        verify_transcript::<E>(before.cs_hash, &after.contributions)
    }
}

// check_same_ratio's error carries a &'static str already, so this just
// threads it through CeremonyError::Ratio without needing to allocate.
fn leak(s: &'static str) -> &'static str {
    s
}

/// Recomputes and checks every contribution's transcript and signature of
/// knowledge, in order. Returns each contribution's hash on success.
pub fn verify_transcript<E: Pairing>(
    cs_hash: [u8; 64],
    contributions: &[PublicKey<E>],
) -> Result<Vec<[u8; 64]>> {
    let mut result = vec![];
    let mut old_delta = E::G1Affine::generator();

    for (i, pubkey) in contributions.iter().enumerate() {
        let hash = hash_cs_pubkeys::<E>(cs_hash, &contributions[0..i], pubkey.s, pubkey.s_delta);
        ensure_unchanged(&pubkey.transcript[..], &hash[..], "transcript")?;

        let r = crate::helpers::hash_to_g2::<E>(&hash).into_affine();

        check_same_ratio::<E>(
            &(pubkey.s, pubkey.s_delta),
            &(r, pubkey.r_delta),
            "signature of knowledge",
        )
        .map_err(|e| CeremonyError::Ratio(leak(e.0)))?;
        check_same_ratio::<E>(
            &(old_delta, pubkey.delta_after),
            &(r, pubkey.r_delta),
            "inconsistent G1 delta",
        )
        .map_err(|e| CeremonyError::Ratio(leak(e.0)))?;

        old_delta = pubkey.delta_after;
        result.push(pubkey.hash());
    }

    Ok(result)
}

fn hash_params<E: Pairing>(params: &ProvingKey<E>) -> Result<[u8; 64]> {
    let mut bytes = Vec::new();
    params
        .serialize_compressed(&mut bytes)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    let mut hasher = Blake2b512::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    Ok(out)
}

// Re-exported so downstream crates (and this crate's own binaries) don't
// need to depend on ark_serialize directly just to (de)serialize a whole
// MPCParameters (params + cs_hash + contributions) as one unit.
impl<E: Pairing> MPCParameters<E> {
    pub fn write<W: std::io::Write>(&self, mut writer: W) -> Result<()> {
        self.params
            .serialize_compressed(&mut writer)
            .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        writer
            .write_all(&self.cs_hash)
            .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        writer
            .write_all(&(self.contributions.len() as u32).to_le_bytes())
            .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        for c in &self.contributions {
            let bytes = c.to_bytes();
            writer
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
            writer
                .write_all(&bytes)
                .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        }
        Ok(())
    }

    pub fn read<R: std::io::Read>(mut reader: R) -> Result<Self> {
        let params = ProvingKey::<E>::deserialize_compressed(&mut reader)
            .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        let mut cs_hash = [0u8; 64];
        reader
            .read_exact(&mut cs_hash)
            .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        let mut count_bytes = [0u8; 4];
        reader
            .read_exact(&mut count_bytes)
            .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
        let count = u32::from_le_bytes(count_bytes);
        let mut contributions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut len_bytes = [0u8; 4];
            reader
                .read_exact(&mut len_bytes)
                .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
            contributions.push(decode_public_key::<E>(&buf)?);
        }
        Ok(Self {
            params,
            cs_hash,
            contributions,
        })
    }
}

fn decode_public_key<E: Pairing>(buf: &[u8]) -> Result<PublicKey<E>> {
    let mut cursor = buf;
    let delta_after = E::G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    let s = E::G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    let s_delta = E::G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    let r_delta = E::G2Affine::deserialize_compressed(&mut cursor)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    if cursor.len() != 64 {
        return Err(CeremonyError::Serialization(
            "malformed PublicKey transcript length".to_string(),
        ));
    }
    let mut transcript = [0u8; 64];
    transcript.copy_from_slice(cursor);
    Ok(PublicKey {
        delta_after,
        s,
        s_delta,
        r_delta,
        transcript,
    })
}
