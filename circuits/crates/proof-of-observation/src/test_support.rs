//! Helpers for building real, valid `ProofOfObservationCircuit` instances
//! outside of this crate's own unit tests — used by the `relay` crate's
//! integration tests so they exercise an actual Groth16 proof end to end
//! rather than a mocked one. Only compiled when the `test-support` feature
//! is enabled; never enable it in a production build.

use crate::{PublicInputs, ProofOfObservationCircuit, Witness};
use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};

use crate::poseidon_params;

/// Builds a small in-memory Merkle tree natively (outside any circuit) and
/// returns everything a prover needs to construct a valid witness for one
/// chosen leaf index: the leaf value, the sibling path, the direction bits,
/// and the root. Mirrors the private helper of the same name in this
/// crate's `tests` module — kept separate rather than shared to avoid
/// coupling this crate's internal test suite to the public test-support
/// surface other crates depend on.
pub fn build_tree(leaves: &[Fr], target_index: usize) -> (Fr, Vec<Fr>, Vec<bool>, Fr) {
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

/// Everything needed to submit a proof-of-observation to a relay: the
/// public inputs (both as the structured type and as the flat vector
/// `Groth16::verify` expects) plus a circuit instance carrying the matching
/// private witness, ready to hand to `Groth16::prove`.
pub struct SampleObservation {
    pub circuit: ProofOfObservationCircuit,
    pub public: PublicInputs,
    pub public_inputs_vec: Vec<Fr>,
}

/// Builds a valid, self-consistent sample observation: a 4-leaf Merkle tree
/// with the target leaf at index 1, an epoch/salt/credential-secret chosen
/// by the caller, and a correctly-derived leaf, root, and nullifier. This is
/// the same construction `proof-of-observation`'s own tests use, factored
/// out and parameterized so callers (e.g. `relay`'s integration tests) can
/// pick their own indicator/epoch/secret rather than being stuck with the
/// hardcoded values baked into the private test helper.
pub fn sample_observation(
    indicator_hash: Fr,
    epoch: Fr,
    salt: Fr,
    credential_secret: Fr,
    min_tier: Fr,
) -> SampleObservation {
    let leaf_cfg = poseidon_params::three_input_config();

    let leaf = CRH::<Fr>::evaluate(&leaf_cfg, vec![indicator_hash, epoch, salt]).unwrap();

    // 4-leaf tree, our leaf sits at index 1; the other three are filler
    // values standing in for a real contributor's other epoch observations.
    let other_leaves = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let leaves = vec![other_leaves[0], leaf, other_leaves[1], other_leaves[2]];
    let (_, merkle_path, path_directions, root) = build_tree(&leaves, 1);

    let nullifier =
        CRH::<Fr>::evaluate(&leaf_cfg, vec![credential_secret, indicator_hash, epoch]).unwrap();

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

    SampleObservation {
        circuit: ProofOfObservationCircuit {
            public: public.clone(),
            witness: Some(witness),
        },
        public,
        public_inputs_vec,
    }
}
