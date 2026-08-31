//! The ultimate end-to-end test: a real Phase 1 (Powers of Tau) ceremony,
//! bridged via `bridge::from_phase1` into starting parameters for the
//! *actual* `ProofOfObservationCircuit`, with a Phase 2 contribution on
//! top — and then a real Groth16 proof built and verified against the
//! result. This is the check that would catch a domain-size or
//! instance-variable-indexing mismatch between this crate's bridge and
//! arkworks' own `LibsnarkReduction` (see `bridge.rs`'s module docs for
//! why that distinction mattered) — no amount of self-consistent
//! bookkeeping checks alone would catch that class of bug; only an actual
//! proof round trip does.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use ceremony::phase1::Accumulator;
use ceremony::{bridge, phase1, MPCParameters};
use proof_of_observation::test_support::sample_observation;

/// Isolates whether a bug is in Phase 1's contribute/verify (already
/// tested separately) or in the bridge itself: builds `from_phase1`
/// straight off an UNCONTRIBUTED accumulator (tau = alpha = beta = 1
/// identically — the simplest possible case) and checks the resulting
/// proving key works, with no Phase 1 contribution math in the loop at
/// all.
#[test]
fn from_phase1_with_trivial_accumulator_produces_a_working_keypair() {
    let mut rng = OsRng;
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let domain_size = bridge::required_domain_size(1767, 7);
    let accumulator = Accumulator::<Bn254>::new(domain_size);

    let proving_key =
        bridge::from_phase1(&accumulator, sample.circuit).expect("bridging a trivial accumulator must succeed");

    let sample2 = sample_observation(
        Fr::from(999u64),
        Fr::from(20260822u64),
        Fr::from(42u64),
        Fr::from(7u64),
        Fr::from(2u64),
        Fr::from(1u64),
    );
    let proof = Groth16::<Bn254>::prove(&proving_key, sample2.circuit, &mut rng).expect("proving must succeed");
    let valid = Groth16::<Bn254>::verify(&proving_key.vk, &sample2.public_inputs_vec, &proof)
        .expect("verification must not error");
    assert!(valid, "a trivial (tau=alpha=beta=1) accumulator bridged to a proving key must still work");
}

#[test]
fn from_phase1_with_one_real_contribution_produces_a_working_keypair() {
    let mut rng = OsRng;
    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let domain_size = bridge::required_domain_size(1767, 7);
    let before = Accumulator::<Bn254>::new(domain_size);
    let (after, pubkey) = phase1::contribute(&before, &mut rng);
    phase1::verify(&before, &after, &pubkey).expect("the single contribution must verify");

    let proving_key =
        bridge::from_phase1(&after, sample.circuit).expect("bridging a once-contributed accumulator must succeed");

    let sample2 = sample_observation(
        Fr::from(999u64),
        Fr::from(20260822u64),
        Fr::from(42u64),
        Fr::from(7u64),
        Fr::from(2u64),
        Fr::from(1u64),
    );
    let proof = Groth16::<Bn254>::prove(&proving_key, sample2.circuit, &mut rng).expect("proving must succeed");
    let valid = Groth16::<Bn254>::verify(&proving_key.vk, &sample2.public_inputs_vec, &proof)
        .expect("verification must not error");
    assert!(valid, "a once-contributed accumulator bridged to a proving key must still work");
}

#[test]
fn phase1_bridged_into_phase2_produces_a_working_keypair() {
    let mut rng = OsRng;

    let sample = sample_observation(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );

    // Determine the real domain size this circuit needs (matching
    // arkworks' own convention exactly, per bridge.rs), then run a real
    // (if small — two contributions, in-memory) Phase 1 ceremony at that
    // size.
    let domain_size = bridge::required_domain_size(1767, 7);
    assert_eq!(domain_size, 2048, "sanity check on the expected domain size for this circuit");

    let mut accumulator = Accumulator::<Bn254>::new(domain_size);
    let mut phase1_pubkeys = vec![];
    let mut phase1_states = vec![accumulator.clone()];
    for _ in 0..2 {
        let (after, pubkey) = phase1::contribute(&accumulator, &mut rng);
        phase1::verify(&accumulator, &after, &pubkey).expect("phase 1 contribution must verify");
        accumulator = after;
        phase1_pubkeys.push(pubkey);
        phase1_states.push(accumulator.clone());
    }
    phase1::verify_chain(&phase1_states, &phase1_pubkeys).expect("the whole phase 1 chain must verify");

    // Bridge Phase 1's output into circuit-specific Phase 2 starting
    // parameters — the piece whose correctness this whole test exists to
    // check.
    let proving_key =
        bridge::from_phase1(&accumulator, sample.circuit).expect("bridging phase 1 output for a real circuit must succeed");

    let cs_hash = {
        use ark_serialize::CanonicalSerialize;
        use blake2::{Blake2b512, Digest};
        let mut bytes = Vec::new();
        proving_key.serialize_compressed(&mut bytes).unwrap();
        let mut hasher = Blake2b512::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&digest);
        out
    };

    let mut params = MPCParameters::<Bn254> {
        params: proving_key,
        cs_hash,
        contributions: vec![],
    };

    // One Phase 2 contribution on top, for good measure — confirms the
    // bridge's output is a valid *starting point* for the delta chain,
    // not just a standalone valid keypair.
    params.contribute(&mut rng).expect("phase 2 contribution on bridged parameters must succeed");

    // The real payoff.
    let sample2 = sample_observation(
        Fr::from(999u64),
        Fr::from(20260822u64),
        Fr::from(42u64),
        Fr::from(7u64),
        Fr::from(2u64),
        Fr::from(1u64),
    );
    let proof = Groth16::<Bn254>::prove(&params.params, sample2.circuit, &mut rng)
        .expect("proving with phase1-bridged, phase2-contributed parameters must succeed");
    let valid = Groth16::<Bn254>::verify(&params.params.vk, &sample2.public_inputs_vec, &proof)
        .expect("verification must not error");
    assert!(
        valid,
        "a real proof built against phase1-bridged parameters must verify — this is the check that would \
         catch a domain-size/indexing mismatch with arkworks' own R1CS-to-QAP reduction"
    );
}
