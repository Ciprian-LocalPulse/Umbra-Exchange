//! proof-of-observation
//!
//! Groth16 circuit for Umbra Exchange's core statement:
//!
//!   "I know a Merkle path from leaf = H(indicator_hash || epoch || salt)
//!    to a published root R, and nullifier = H(credential_secret ||
//!    indicator_hash || epoch)."
//!
//! STATUS (Phase 0 -> 1): the Merkle-inclusion and nullifier constraints
//! below are implemented and constrain real witness values (not just
//! allocate them) — see `tests` for a happy-path and two adversarial
//! (tampered) cases. What is explicitly NOT yet enforced is the
//! credential-tier claim: `min_tier` is allocated as a public input but
//! nothing currently ties it to `credential_secret`. A proof from this
//! circuit today shows "someone knows a path to this root and this
//! nullifier is correctly derived" — it does NOT yet show "the prover
//! holds a validly-issued credential of the claimed tier." Do not treat
//! `min_tier` as enforced until this notice is removed; see
//! docs/PROTOCOL_SPEC.md §2 for why that gadget is blocked on a
//! governance decision, not a technical one.
//!
//! Also unimplemented: the trusted setup ceremony. Proofs produced with a
//! locally-generated proving key (e.g. in tests) are not sound against a
//! party that could have retained toxic waste from that local setup — see
//! docs/THREAT_MODEL.md.

pub mod poseidon_params;

use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::{
    CRHGadget, CRHParametersVar, TwoToOneCRHGadget,
};
use ark_crypto_primitives::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

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
    /// Minimum tier being claimed (0-3). NOT YET ENFORCED — see module docs.
    pub min_tier: Fr,
}

/// Private witness known only to the contributor.
#[derive(Clone)]
pub struct Witness {
    /// Per-leaf salt, so the same indicator submitted twice by different
    /// contributors doesn't collide on the same leaf value.
    pub salt: Fr,
    /// Sibling hashes along the Merkle path from leaf to root, ordered
    /// leaf-to-root (index 0 is the leaf's sibling).
    pub merkle_path: Vec<Fr>,
    /// Direction bits, same order as `merkle_path`: `false` means the
    /// current node is the left input to the next compression step,
    /// `true` means it's the right input.
    pub path_directions: Vec<bool>,
    /// Secret backing the contributor's anonymous credential. Used today
    /// only as a nullifier input; see module docs re: tier enforcement.
    pub credential_secret: Fr,
}

/// The R1CS circuit tying public inputs and witness together.
pub struct ProofOfObservationCircuit {
    pub public: PublicInputs,
    pub witness: Option<Witness>,
}

impl ConstraintSynthesizer<Fr> for ProofOfObservationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- public inputs --------------------------------------------------
        let indicator_hash = FpVar::new_input(cs.clone(), || Ok(self.public.indicator_hash))?;
        let epoch = FpVar::new_input(cs.clone(), || Ok(self.public.epoch))?;
        let root = FpVar::new_input(cs.clone(), || Ok(self.public.root))?;
        let nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.nullifier))?;
        let _min_tier = FpVar::new_input(cs.clone(), || Ok(self.public.min_tier))?;

        // --- witness ---------------------------------------------------------
        let witness = self.witness.ok_or(SynthesisError::AssignmentMissing)?;
        assert_eq!(
            witness.merkle_path.len(),
            witness.path_directions.len(),
            "merkle_path and path_directions must be the same length"
        );

        let salt = FpVar::new_witness(cs.clone(), || Ok(witness.salt))?;
        let credential_secret = FpVar::new_witness(cs.clone(), || Ok(witness.credential_secret))?;

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

        // --- fold the Merkle path up to a computed root -----------------------
        let mut current = leaf;
        for (sibling, is_right) in path_nodes.iter().zip(path_dirs.iter()) {
            // is_right == true  => current is the right child: compress(sibling, current)
            // is_right == false => current is the left child:  compress(current, sibling)
            let left = is_right.select(sibling, &current)?;
            let right = is_right.select(&current, sibling)?;
            current = TwoToOneCRHGadget::<Fr>::compress(&node_params, &left, &right)?;
        }
        current.enforce_equal(&root)?;

        // --- nullifier = Poseidon(credential_secret, indicator_hash, epoch) --
        let computed_nullifier =
            CRHGadget::<Fr>::evaluate(&leaf_params, &[credential_secret, indicator_hash, epoch])?;
        computed_nullifier.enforce_equal(&nullifier)?;

        // TODO (blocked on docs/PROTOCOL_SPEC.md §2, credential issuance
        // governance, not a cryptography question): enforce that
        // `credential_secret` corresponds to a validly-issued credential of
        // tier >= min_tier. Until this lands, `min_tier` is an unconstrained
        // public input — see module-level docs.

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

        let min_tier = Fr::from(1u64);

        let public = PublicInputs {
            indicator_hash,
            epoch,
            root,
            nullifier,
            min_tier,
        };
        let public_inputs_vec = vec![indicator_hash, epoch, root, nullifier, min_tier];

        let witness = Witness {
            salt,
            merkle_path,
            path_directions,
            credential_secret,
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
