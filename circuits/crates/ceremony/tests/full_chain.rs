//! End-to-end test of the ceremony machinery against the *real*
//! `ProofOfObservationCircuit` — not a toy circuit. Confirms two
//! distinct things, both necessary:
//!
//! 1. The ceremony's own bookkeeping is self-consistent (`verify` accepts
//!    a correctly-run chain of contributions, rejects a tampered one).
//! 2. The parameters that fall out the other end are still a genuinely
//!    *functioning* Groth16 keypair for our circuit — a real proof built
//!    with the final proving key actually verifies against the final
//!    verifying key. This is the check that would catch a subtle
//!    porting mistake in the delta re-randomization math that the
//!    bookkeeping checks alone might not.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use ceremony::MPCParameters;
use proof_of_observation::test_support::sample_observation;

#[test]
fn full_ceremony_chain_produces_a_working_keypair() {
    let mut rng = OsRng;

    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );

    let mut params = MPCParameters::<Bn254>::new_placeholder(sample.circuit, &mut rng)
        .expect("building placeholder parameters for a well-formed circuit must succeed");

    // Three independent contributors, one after another — this is the
    // actual security property: as long as at least one destroyed their
    // secret (which, in Rust, every one of them did — `delta` goes out
    // of scope at the end of each `contribute` call), the final
    // parameters are sound even though this test technically "knows"
    // each contribution happened, because it's the code path, not this
    // particular run, that matters.
    let mut history = vec![clone_params(&params)];
    for _ in 0..3 {
        let mut next = clone_params(&params);
        next.contribute(&mut rng)
            .expect("contribution must succeed");
        params
            .verify(&next)
            .expect("a correctly-produced contribution must verify");
        params = next;
        history.push(clone_params(&params));
    }

    // Verify the WHOLE chain from the very start, not just the last hop.
    for window in history.windows(2) {
        window[0]
            .verify(&window[1])
            .expect("every hop in the contribution chain must independently verify");
    }

    // The real payoff: build an actual proof with the final proving key
    // and confirm it verifies against the final verifying key.
    let sample2 = sample_observation(
        Fr::from(999u64),
        Fr::from(20260822u64),
        Fr::from(42u64),
        Fr::from(7u64),
        Fr::from(2u64),
        Fr::from(1u64),
    );
    let proof = Groth16::<Bn254>::prove(&params.params, sample2.circuit, &mut rng)
        .expect("proving with the ceremony's final proving key must succeed");
    let valid = Groth16::<Bn254>::verify(&params.params.vk, &sample2.public_inputs_vec, &proof)
        .expect("verification must not error");
    assert!(
        valid,
        "a real proof built with the ceremony's final proving key must verify against its final verifying key"
    );
}

#[test]
fn tampered_contribution_is_rejected() {
    let mut rng = OsRng;
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let params = MPCParameters::<Bn254>::new_placeholder(sample.circuit, &mut rng).unwrap();

    let mut tampered = clone_params(&params);
    tampered.contribute(&mut rng).unwrap();
    // Tamper with the contribution's claimed delta_after — a bit flip in
    // one coordinate, simulating either corruption or an actively
    // dishonest contributor claiming a different result than they
    // actually computed.
    let bad_point = (tampered.contributions[0].delta_after * ark_bn254::Fr::from(2u64)).into();
    tampered.contributions[0].delta_after = bad_point;

    let result = params.verify(&tampered);
    assert!(
        result.is_err(),
        "a tampered contribution must be rejected, not silently accepted"
    );
}

#[test]
fn contribution_from_wrong_cs_hash_is_rejected() {
    // Two independent placeholder parameter sets for the same circuit
    // will, in general, have different cs_hash values (new_placeholder
    // samples fresh alpha/beta/gamma/generators each time) — simulating
    // "a contribution meant for a different ceremony" without needing a
    // structurally different circuit.
    let mut rng = OsRng;
    let sample_a = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let sample_b = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let params_a = MPCParameters::<Bn254>::new_placeholder(sample_a.circuit, &mut rng).unwrap();
    let mut params_b = MPCParameters::<Bn254>::new_placeholder(sample_b.circuit, &mut rng).unwrap();
    assert_ne!(
        params_a.cs_hash, params_b.cs_hash,
        "two independent placeholder setups should not coincidentally share a cs_hash"
    );

    params_b.contribute(&mut rng).unwrap();
    let result = params_a.verify(&params_b);
    assert!(
        result.is_err(),
        "a contribution against a different cs_hash must be rejected"
    );
}

#[test]
fn write_read_round_trip_preserves_everything_verify_needs() {
    let mut rng = OsRng;
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let mut params = MPCParameters::<Bn254>::new_placeholder(sample.circuit, &mut rng).unwrap();
    params.contribute(&mut rng).unwrap();

    let mut bytes = Vec::new();
    params.write(&mut bytes).unwrap();
    let read_back = MPCParameters::<Bn254>::read(&bytes[..]).unwrap();

    assert_eq!(params.cs_hash, read_back.cs_hash);
    assert_eq!(params.contributions.len(), read_back.contributions.len());
    assert_eq!(params.params.vk.delta_g2, read_back.params.vk.delta_g2);
    assert_eq!(params.params.delta_g1, read_back.params.delta_g1);
}

fn clone_params(p: &MPCParameters<Bn254>) -> MPCParameters<Bn254> {
    MPCParameters {
        params: p.params.clone(),
        cs_hash: p.cs_hash,
        contributions: p.contributions.clone(),
    }
}
