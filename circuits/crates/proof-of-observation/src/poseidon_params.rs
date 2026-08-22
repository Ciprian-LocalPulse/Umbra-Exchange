//! Poseidon parameters for BN254, adapted from the `light-poseidon` crate
//! (maintained by Light Protocol) into the `PoseidonConfig` shape expected
//! by `ark-crypto-primitives`'s sponge/CRH gadgets.
//!
//! Provenance matters for a security-sensitive constant set like this one,
//! so: these are the standard circomlib/iden3 "bn254_x5" parameters
//! (x^5 S-box, generated via the official reference script from the
//! Poseidon paper — see `light_poseidon::parameters::bn254_x5` for the
//! exact `sage generate_parameters_grain.sage` invocation used). This is
//! the same constant set used across a large share of production BN254
//! ZK systems, not something generated ad hoc for this project. That's a
//! reasonable trust anchor for Phase 0/1, but it is not a substitute for
//! an independent audit before anything here is relied on for real
//! security guarantees — see docs/THREAT_MODEL.md.
//!
//! `light-poseidon` stores round constants as a flat `Vec<F>`; this module
//! reshapes that into `ark-crypto-primitives`'s `ark[round][state_index]`
//! layout and picks rate/capacity = (width - 1) / 1, matching how
//! `light-poseidon` itself derives `width` from `nr_inputs + 1`.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;

/// Build a `PoseidonConfig<Fr>` for a given state width (rate + capacity,
/// capacity fixed at 1). `width = 3` is the two-to-one compression used for
/// Merkle nodes; `width = 4` is the three-input hash used for both the leaf
/// commitment and the nullifier.
fn config_for_width(width: u8) -> PoseidonConfig<Fr> {
    let params = get_poseidon_parameters::<Fr>(width)
        .expect("light-poseidon: unsupported width — only 2..=13 are defined");

    let w = width as usize;
    assert_eq!(
        params.ark.len() % w,
        0,
        "round-constant count isn't a multiple of the state width; parameter source may have changed shape"
    );
    let ark: Vec<Vec<Fr>> = params.ark.chunks(w).map(|chunk| chunk.to_vec()).collect();

    PoseidonConfig {
        full_rounds: params.full_rounds,
        partial_rounds: params.partial_rounds,
        alpha: params.alpha,
        ark,
        mds: params.mds,
        rate: w - 1,
        capacity: 1,
    }
}

/// Two-to-one compression parameters (Merkle node hashing): width 3.
pub fn merkle_node_config() -> PoseidonConfig<Fr> {
    config_for_width(3)
}

/// Three-input hash parameters (leaf commitment, nullifier): width 4.
pub fn three_input_config() -> PoseidonConfig<Fr> {
    config_for_width(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_build_without_panicking_and_have_expected_shape() {
        let node_cfg = merkle_node_config();
        assert_eq!(node_cfg.rate, 2);
        assert_eq!(node_cfg.capacity, 1);
        assert_eq!(node_cfg.ark.len(), node_cfg.full_rounds + node_cfg.partial_rounds);
        assert!(node_cfg.ark.iter().all(|row| row.len() == 3));
        assert_eq!(node_cfg.mds.len(), 3);

        let three_cfg = three_input_config();
        assert_eq!(three_cfg.rate, 3);
        assert_eq!(three_cfg.capacity, 1);
        assert_eq!(
            three_cfg.ark.len(),
            three_cfg.full_rounds + three_cfg.partial_rounds
        );
        assert!(three_cfg.ark.iter().all(|row| row.len() == 4));
        assert_eq!(three_cfg.mds.len(), 4);
    }
}
