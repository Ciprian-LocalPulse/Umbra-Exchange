//! proof-of-observation
//!
//! Groth16 circuit for Umbra Exchange's core statement:
//!
//!   "I know a Merkle path from leaf = H(indicator_hash || epoch || salt)
//!    to a published root R; nullifier = H(credential_secret ||
//!    indicator_hash || epoch); and I know a Merkle path from
//!    credential_leaf = H(credential_secret || credential_tier ||
//!    CREDENTIAL_DOMAIN_TAG) to a published credential_root, where
//!    credential_tier >= min_tier."
//!
//! STATUS (Phase 1): all four sub-statements above are implemented and
//! constrain real witness values (not just allocated) — see `tests` for a
//! happy path and adversarial (tampered) cases covering each one,
//! including the credential-tier gate specifically. A proof from this
//! circuit shows both "someone knows a path to this indicator root with a
//! correctly-derived nullifier" AND "the same secret backs a credential,
//! recorded in a tree the issuer(s) published, whose tier is at least the
//! claimed min_tier" — without revealing which credential or its exact
//! tier.
//!
//! What this does NOT show, and can't from cryptography alone: that
//! `credential_root` was published by a legitimate issuer running sound
//! vetting, or that issuance itself is Sybil-resistant. That's a
//! governance question, tracked in docs/PROTOCOL_SPEC.md §2, not something
//! this circuit can constrain — the circuit can only prove "this secret is
//! in the tree at that root with that tier," not "the tree's contents are
//! trustworthy." A relay/consumer's trust in a given `credential_root`
//! ultimately traces back to trusting whoever published it.
//!
//! Also unimplemented: the trusted setup ceremony. Proofs produced with a
//! locally-generated proving key (e.g. in tests) are not sound against a
//! party that could have retained toxic waste from that local setup — see
//! docs/THREAT_MODEL.md.

pub mod poseidon_params;

/// Test-support helpers, exposed behind the `test-support` feature so other
/// crates in this workspace (currently `relay`) can build real, valid
/// witnesses/proofs in their own integration tests without duplicating the
/// Merkle-tree-building logic that already lives in this crate's own
/// `#[cfg(test)]` module. Never enable this feature in a non-dev build.
#[cfg(feature = "test-support")]
pub mod test_support;

use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::{
    CRHGadget, CRHParametersVar, TwoToOneCRHGadget,
};
use ark_crypto_primitives::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Domain-separation tag mixed into every credential leaf, so a credential
/// leaf can never be structurally confused with an indicator leaf even if
/// some future change makes their other inputs overlap in shape. Derived
/// from an ASCII tag rather than a bare small integer so it's obviously
/// not "just another witness value" to anyone reading a leaf's preimage.
fn credential_domain_tag() -> Fr {
    Fr::from_le_bytes_mod_order(b"UMBRA_CREDENTIAL_LEAF_V1")
}

/// The four valid tiers, per docs/PROTOCOL_SPEC.md.
const MAX_TIER: u64 = 3;

/// Enforces that `v` is one of the `MAX_TIER + 1` valid tier values
/// (currently {0,1,2,3}) via `(v)(v-1)(v-2)(v-3) = 0`. This is a single
/// degree-4 polynomial constraint — far cheaper than a general bit-decomposition
/// range check, and exact (not just "small enough") precisely because the
/// tier space is fixed and tiny. If `docs/PROTOCOL_SPEC.md` ever grows more
/// tiers, `MAX_TIER` and this product need to grow with it.
fn enforce_is_valid_tier(v: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let mut product = v.clone();
    for k in 1..=MAX_TIER {
        product *= v - FpVar::constant(Fr::from(k));
    }
    product.enforce_equal(&FpVar::constant(Fr::from(0u64)))
}

/// Enforces `tier >= min_tier`, given both are already known to be valid
/// tiers (callers must have called `enforce_is_valid_tier` on both first).
/// `tier - min_tier` lands in the field as one of `{0,1,2,3}` exactly when
/// `tier >= min_tier` (as integers 0-3); any "negative" case wraps around
/// to a huge field element that fails the same four-way check. This reuses
/// `enforce_is_valid_tier` rather than a separate bit-comparison gadget.
fn enforce_tier_at_least(tier: &FpVar<Fr>, min_tier: &FpVar<Fr>) -> Result<(), SynthesisError> {
    enforce_is_valid_tier(&(tier - min_tier))
}

/// Public inputs to the proof-of-observation statement. These are exactly
/// the values a verifier (relay or downstream consumer) sees and checks
/// against; everything else stays private to the prover.
#[derive(Clone)]
pub struct PublicInputs {
    /// Poseidon(normalized_indicator) — the indicator being disclosed.
    pub indicator_hash: Fr,
    /// Epoch identifier (e.g. Unix day number).
    pub epoch: Fr,
    /// The Merkle root the contributor previously published for this epoch.
    pub root: Fr,
    /// Poseidon(credential_secret, indicator_hash, epoch) — prevents
    /// double-counting the same observation.
    pub nullifier: Fr,
    /// Minimum tier being claimed (0-3), cryptographically enforced (see
    /// module docs) against whatever tier the credential tree records for
    /// this prover's credential_secret.
    pub min_tier: Fr,
    /// Root of the issuer-published credential tree, whose leaves are
    /// `H(credential_secret, credential_tier, CREDENTIAL_DOMAIN_TAG)`.
    pub credential_root: Fr,
}

/// Private witness known only to the contributor.
#[derive(Clone)]
pub struct Witness {
    /// Per-leaf salt, so the same indicator submitted twice by different
    /// contributors doesn't collide on the same leaf value.
    pub salt: Fr,
    /// Sibling hashes along the indicator Merkle path from leaf to root,
    /// ordered leaf-to-root (index 0 is the leaf's sibling).
    pub merkle_path: Vec<Fr>,
    /// Direction bits for `merkle_path`: `false` means the current node is
    /// the left input to the next compression step, `true` means right.
    pub path_directions: Vec<bool>,
    /// Secret backing the contributor's anonymous credential. Used both as
    /// a nullifier input and, now, as a credential-leaf input.
    pub credential_secret: Fr,
    /// The tier actually recorded for this credential in the credential
    /// tree. Private — the proof only reveals `credential_tier >=
    /// min_tier`, not the exact tier.
    pub credential_tier: Fr,
    /// Sibling hashes along the credential Merkle path, same ordering
    /// convention as `merkle_path`.
    pub credential_merkle_path: Vec<Fr>,
    /// Direction bits for `credential_merkle_path`.
    pub credential_path_directions: Vec<bool>,
}

/// The R1CS circuit tying public inputs and witness together.
pub struct ProofOfObservationCircuit {
    pub public: PublicInputs,
    pub witness: Option<Witness>,
}

/// Folds a leaf up a Merkle path to a root, inside the circuit. Shared by
/// both the indicator tree and the credential tree — same hash function,
/// same direction-bit convention, just different (leaf, path, root)
/// triples, so there's no reason to write this twice.
fn fold_merkle_path(
    node_params: &CRHParametersVar<Fr>,
    leaf: FpVar<Fr>,
    path_nodes: &[FpVar<Fr>],
    path_dirs: &[Boolean<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut current = leaf;
    for (sibling, is_right) in path_nodes.iter().zip(path_dirs.iter()) {
        // is_right == true  => current is the right child: compress(sibling, current)
        // is_right == false => current is the left child:  compress(current, sibling)
        let left = is_right.select(sibling, &current)?;
        let right = is_right.select(&current, sibling)?;
        current = TwoToOneCRHGadget::<Fr>::compress(node_params, &left, &right)?;
    }
    Ok(current)
}

impl ConstraintSynthesizer<Fr> for ProofOfObservationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- public inputs --------------------------------------------------
        let indicator_hash = FpVar::new_input(cs.clone(), || Ok(self.public.indicator_hash))?;
        let epoch = FpVar::new_input(cs.clone(), || Ok(self.public.epoch))?;
        let root = FpVar::new_input(cs.clone(), || Ok(self.public.root))?;
        let nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.nullifier))?;
        let min_tier = FpVar::new_input(cs.clone(), || Ok(self.public.min_tier))?;
        let credential_root = FpVar::new_input(cs.clone(), || Ok(self.public.credential_root))?;

        // --- witness ---------------------------------------------------------
        let witness = self.witness.ok_or(SynthesisError::AssignmentMissing)?;
        assert_eq!(
            witness.merkle_path.len(),
            witness.path_directions.len(),
            "merkle_path and path_directions must be the same length"
        );
        assert_eq!(
            witness.credential_merkle_path.len(),
            witness.credential_path_directions.len(),
            "credential_merkle_path and credential_path_directions must be the same length"
        );

        let salt = FpVar::new_witness(cs.clone(), || Ok(witness.salt))?;
        let credential_secret = FpVar::new_witness(cs.clone(), || Ok(witness.credential_secret))?;
        let credential_tier = FpVar::new_witness(cs.clone(), || Ok(witness.credential_tier))?;

        let path_nodes: Vec<FpVar<Fr>> = witness
            .merkle_path
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
            .collect::<Result<_, _>>()?;
        let path_dirs: Vec<Boolean<Fr>> = witness
            .path_directions
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        let credential_path_nodes: Vec<FpVar<Fr>> = witness
            .credential_merkle_path
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
            .collect::<Result<_, _>>()?;
        let credential_path_dirs: Vec<Boolean<Fr>> = witness
            .credential_path_directions
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        // --- Poseidon parameters (constants, not allocated as variables) ----
        let leaf_params = CRHParametersVar {
            parameters: poseidon_params::three_input_config(),
        };
        let node_params = CRHParametersVar {
            parameters: poseidon_params::merkle_node_config(),
        };

        // --- leaf = Poseidon(indicator_hash, epoch, salt) --------------------
        let leaf = CRHGadget::<Fr>::evaluate(
            &leaf_params,
            &[indicator_hash.clone(), epoch.clone(), salt],
        )?;
        let computed_root = fold_merkle_path(&node_params, leaf, &path_nodes, &path_dirs)?;
        computed_root.enforce_equal(&root)?;

        // --- nullifier = Poseidon(credential_secret, indicator_hash, epoch) --
        let computed_nullifier = CRHGadget::<Fr>::evaluate(
            &leaf_params,
            &[credential_secret.clone(), indicator_hash, epoch],
        )?;
        computed_nullifier.enforce_equal(&nullifier)?;

        // --- credential-tier gate ---------------------------------------------
        // credential_leaf = Poseidon(credential_secret, credential_tier, DOMAIN_TAG)
        let domain_tag = FpVar::constant(credential_domain_tag());
        let credential_leaf = CRHGadget::<Fr>::evaluate(
            &leaf_params,
            &[credential_secret, credential_tier.clone(), domain_tag],
        )?;
        let computed_credential_root = fold_merkle_path(
            &node_params,
            credential_leaf,
            &credential_path_nodes,
            &credential_path_dirs,
        )?;
        computed_credential_root.enforce_equal(&credential_root)?;

        enforce_is_valid_tier(&credential_tier)?;
        enforce_is_valid_tier(&min_tier)?;
        enforce_tier_at_least(&credential_tier, &min_tier)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};
    use ark_snark::SNARK;
    use rand::{rngs::StdRng, SeedableRng};

    /// Builds a small in-memory Merkle tree (depth = leaves.len().ilog2())
    /// natively (outside any circuit) and returns everything a prover needs
    /// to construct a valid witness for one chosen leaf index: the leaf
    /// value, the sibling path, the direction bits, and the root.
    fn build_tree(leaves: &[Fr], target_index: usize) -> (Fr, Vec<Fr>, Vec<bool>, Fr) {
        let node_cfg = poseidon_params::merkle_node_config();
        let mut level = leaves.to_vec();
        let mut index = target_index;
        let mut path = Vec::new();
        let mut dirs = Vec::new();

        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let (l, r) = (pair[0], pair[1]);
                next_level.push(TwoToOneCRH::<Fr>::compress(&node_cfg, l, r).unwrap());
            }

            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };
            path.push(level[sibling_index]);
            dirs.push(is_right);

            level = next_level;
            index /= 2;
        }

        (leaves[target_index], path, dirs, level[0])
    }

    fn sample_circuit_and_public_inputs() -> (ProofOfObservationCircuit, Vec<Fr>) {
        sample_circuit_with_tier(Fr::from(2u64), Fr::from(1u64))
    }

    /// Same construction as `sample_circuit_and_public_inputs`, but with
    /// caller-chosen `credential_tier` (private, actually recorded in the
    /// credential tree) and `min_tier` (public, being claimed) — so tests
    /// can build both satisfying and deliberately-unsatisfying tier claims.
    fn sample_circuit_with_tier(
        credential_tier: Fr,
        min_tier: Fr,
    ) -> (ProofOfObservationCircuit, Vec<Fr>) {
        let leaf_cfg = poseidon_params::three_input_config();

        let indicator_hash = Fr::from(4242u64);
        let epoch = Fr::from(20260822u64);
        let salt = Fr::from(777u64);
        let credential_secret = Fr::from(999u64);

        let leaf = CRH::<Fr>::evaluate(&leaf_cfg, vec![indicator_hash, epoch, salt]).unwrap();

        // 4-leaf tree, our leaf sits at index 1; the other three are filler.
        let other_leaves = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let leaves = vec![other_leaves[0], leaf, other_leaves[1], other_leaves[2]];
        let (_, merkle_path, path_directions, root) = build_tree(&leaves, 1);

        let nullifier =
            CRH::<Fr>::evaluate(&leaf_cfg, vec![credential_secret, indicator_hash, epoch]).unwrap();

        let credential_leaf = CRH::<Fr>::evaluate(
            &leaf_cfg,
            vec![credential_secret, credential_tier, credential_domain_tag()],
        )
        .unwrap();
        let other_credential_leaves = [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)];
        let credential_leaves = vec![
            other_credential_leaves[0],
            credential_leaf,
            other_credential_leaves[1],
            other_credential_leaves[2],
        ];
        let (_, credential_merkle_path, credential_path_directions, credential_root) =
            build_tree(&credential_leaves, 1);

        let public = PublicInputs {
            indicator_hash,
            epoch,
            root,
            nullifier,
            min_tier,
            credential_root,
        };
        let public_inputs_vec = vec![
            indicator_hash,
            epoch,
            root,
            nullifier,
            min_tier,
            credential_root,
        ];

        let witness = Witness {
            salt,
            merkle_path,
            path_directions,
            credential_secret,
            credential_tier,
            credential_merkle_path,
            credential_path_directions,
        };

        (
            ProofOfObservationCircuit {
                public,
                witness: Some(witness),
            },
            public_inputs_vec,
        )
    }

    #[test]
    fn happy_path_satisfies_all_constraints() {
        let (circuit, _) = sample_circuit_and_public_inputs();
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "a correctly constructed witness must satisfy the circuit"
        );
    }

    #[test]
    fn tampered_root_fails_to_satisfy() {
        let (mut circuit, _) = sample_circuit_and_public_inputs();
        circuit.public.root += Fr::from(1u64); // corrupt the claimed root
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "a mismatched root must NOT satisfy the circuit"
        );
    }

    #[test]
    fn tampered_nullifier_fails_to_satisfy() {
        let (mut circuit, _) = sample_circuit_and_public_inputs();
        circuit.public.nullifier += Fr::from(1u64); // wrong nullifier claim
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "a mismatched nullifier must NOT satisfy the circuit"
        );
    }

    #[test]
    fn wrong_leaf_indicator_fails_to_satisfy() {
        // Prover claims a different indicator_hash than the one actually
        // baked into the leaf that the Merkle path proves membership for.
        let (mut circuit, _) = sample_circuit_and_public_inputs();
        circuit.public.indicator_hash += Fr::from(1u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "claiming a different indicator than what's in the leaf must fail"
        );
    }

    #[test]
    fn credential_tier_exactly_equal_to_min_tier_satisfies() {
        let (circuit, _) = sample_circuit_with_tier(Fr::from(2u64), Fr::from(2u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "credential_tier == min_tier is a valid claim (>=), must satisfy"
        );
    }

    #[test]
    fn credential_tier_above_min_tier_satisfies() {
        let (circuit, _) = sample_circuit_with_tier(Fr::from(3u64), Fr::from(0u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "a tier-3 credential must satisfy a tier-0-or-higher claim"
        );
    }

    #[test]
    fn credential_tier_below_min_tier_fails_to_satisfy() {
        // This is the regression test for the vulnerability found and
        // patched at the relay layer in an earlier commit: a tier-0
        // credential must NOT be able to satisfy a min_tier=3 claim. Before
        // this gadget existed, the circuit had no opinion on this at all.
        let (circuit, _) = sample_circuit_with_tier(Fr::from(0u64), Fr::from(3u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "a tier-0 credential must NOT satisfy a min_tier=3 claim"
        );
    }

    #[test]
    fn out_of_range_credential_tier_fails_to_satisfy() {
        // Tier 4 doesn't exist (valid tiers are 0-3, per
        // docs/PROTOCOL_SPEC.md); enforce_is_valid_tier must reject it even
        // though 4 >= 1 would otherwise look like a satisfying claim.
        let (circuit, _) = sample_circuit_with_tier(Fr::from(4u64), Fr::from(1u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "credential_tier outside {{0,1,2,3}} must not satisfy, regardless of min_tier"
        );
    }

    #[test]
    fn out_of_range_min_tier_fails_to_satisfy() {
        // A relay should reject this at the API layer too (it's not a
        // meaningful claim), but the circuit itself must also refuse to be
        // satisfied by a public min_tier outside {0,1,2,3} — a public
        // input is still attacker-controlled input.
        let (circuit, _) = sample_circuit_with_tier(Fr::from(3u64), Fr::from(9u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "min_tier outside {{0,1,2,3}} must not satisfy, even with a valid high-tier credential"
        );
    }

    #[test]
    fn tampered_credential_root_fails_to_satisfy() {
        let (mut circuit, _) = sample_circuit_and_public_inputs();
        circuit.public.credential_root += Fr::from(1u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "a mismatched credential_root must NOT satisfy the circuit"
        );
    }

    #[test]
    fn credential_secret_not_in_credential_tree_fails_to_satisfy() {
        // A valid indicator-tree membership and a valid nullifier, but the
        // credential_secret used doesn't actually correspond to the leaf
        // the credential Merkle path proves — i.e. someone tries to borrow
        // someone else's credential tree without knowing a real secret in
        // it. Simulated here by tampering the witness's credential_tier
        // after the tree was built for a different tier, which desyncs
        // credential_leaf from what the credential Merkle path actually
        // proves membership for.
        let (mut circuit, _) = sample_circuit_and_public_inputs();
        if let Some(w) = circuit.witness.as_mut() {
            w.credential_tier += Fr::from(1u64);
        }
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "a credential leaf that doesn't match the proven Merkle path must NOT satisfy"
        );
    }

    /// Full Groth16 round trip: local (non-ceremony) setup, prove, verify.
    /// This is NOT a substitute for a real trusted setup — see module docs
    /// and docs/THREAT_MODEL.md — but it does prove the circuit is
    /// well-formed enough to actually produce and verify a Groth16 proof,
    /// not just satisfy an R1CS constraint system in isolation.
    #[test]
    fn groth16_round_trip_local_setup() {
        let (circuit_for_setup, _) = sample_circuit_and_public_inputs();
        // Setup only needs the circuit's *shape*; give it a fresh instance
        // with the same structure but no requirement that witness values
        // match what we'll prove with (they don't need to for key generation).
        let mut rng = StdRng::seed_from_u64(20260822);
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            ProofOfObservationCircuit {
                public: circuit_for_setup.public.clone(),
                witness: circuit_for_setup.witness.clone(),
            },
            &mut rng,
        )
        .expect("local (non-ceremony) Groth16 setup should succeed for a well-formed circuit");

        let (prove_circuit, public_inputs_vec) = sample_circuit_and_public_inputs();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, prove_circuit, &mut rng)
            .expect("proving should succeed with a valid witness");

        let valid = Groth16::<ark_bn254::Bn254>::verify(&vk, &public_inputs_vec, &proof)
            .expect("verification should not error");
        assert!(valid, "a valid proof must verify");

        // Sanity check the negative case too: wrong public inputs must not verify.
        let mut bad_inputs = public_inputs_vec.clone();
        bad_inputs[2] += Fr::from(1u64); // corrupt the claimed root
        let invalid = Groth16::<ark_bn254::Bn254>::verify(&vk, &bad_inputs, &proof)
            .expect("verification should not error even when it returns false");
        assert!(
            !invalid,
            "a proof must not verify against a tampered public input"
        );
    }
}
