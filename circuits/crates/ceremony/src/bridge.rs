//! Bridges Phase 1's circuit-independent `Accumulator` to a
//! circuit-specific Phase 2 starting point (an `ark_groth16::ProvingKey`
//! with `delta = 1`, ready for `MPCParameters::contribute` to build on).
//!
//! # Why this isn't a port of celo-org/snark-setup's `eval()`
//!
//! It would have been simpler to port celo-org's `phase2::parameters::eval`
//! directly — but doing so would have silently produced parameters
//! **incompatible with this workspace's actual `ark_groth16::Groth16::prove`**.
//! Checked directly against arkworks 0.4's own R1CS-to-QAP reduction
//! (`ark_groth16::r1cs_to_qap::LibsnarkReduction::instance_map_with_evaluation`,
//! the function `Groth16::prove`/`verify` use internally) before writing
//! this: it uses a QAP domain of size `num_constraints +
//! num_instance_variables` (not just `num_constraints`, which is what
//! celo-org's simpler `process_matrix` assumes) and a specific
//! "instance-consistency" block that assigns the Lagrange coefficients at
//! domain positions `[num_constraints, num_constraints +
//! num_instance_variables)` directly to the first `num_instance_variables`
//! QAP-variable slots. Reusing a different-but-plausible-looking
//! convention here would have produced a proving key that either fails
//! outright or — worse — silently mismatches what `Groth16::prove`
//! expects. So this module replicates `LibsnarkReduction`'s *exact*
//! domain-size and indexing convention, just computed with curve points
//! via FFT (`ark_poly`'s `ifft_in_place`, confirmed to work correctly on
//! curve group elements in an isolated check before this was written) —
//! since real Phase 1 output only ever gives us `tau^i * G`, never `tau`
//! itself.
//!
//! `alpha`/`beta` weighting and the H-query construction below ARE the
//! same algebraic identities celo-org's implementation uses (these are
//! standard Groth16 formulas, not `LibsnarkReduction`-specific), so those
//! parts are a faithful port of that logic; only the *domain size and
//! instance-variable indexing* needed to be re-derived from arkworks' own
//! source instead.
//!
//! Not independently audited; see `docs/CEREMONY.md`.

use crate::phase1::Accumulator;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_std::Zero;

#[derive(Debug)]
pub enum BridgeError {
    Synthesis(SynthesisError),
    DomainTooSmall,
    AccumulatorTooSmall { needed: usize, have: usize },
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Synthesis(e) => write!(f, "constraint synthesis error: {e}"),
            BridgeError::DomainTooSmall => write!(
                f,
                "could not construct an evaluation domain of the required size"
            ),
            BridgeError::AccumulatorTooSmall { needed, have } => {
                write!(f, "Phase 1 accumulator is too small for this circuit: need degree {needed}, have {have}")
            }
        }
    }
}
impl std::error::Error for BridgeError {}

/// The QAP domain size a circuit with `num_constraints` constraints and
/// `num_instance_variables` instance variables needs, matching
/// `ark_groth16::r1cs_to_qap::LibsnarkReduction` exactly (checked against
/// its source, not assumed). A Phase 1 accumulator must have been built
/// with at least this size for [`from_phase1`] to work.
pub fn required_domain_size(num_constraints: usize, num_instance_variables: usize) -> usize {
    Radix2EvaluationDomain::<ark_bn254::Fr>::compute_size_of_domain(
        num_constraints + num_instance_variables,
    )
    .unwrap_or(0)
}

/// Debug-only: exposes the intermediate Lagrange tables `from_phase1`
/// computes internally, so tests can directly cross-check them against a
/// scalar ground truth rather than only observing the final assembled
/// keys. Not part of the crate's normal public surface in spirit — kept
/// `pub` only because integration tests in `tests/` need it.
type DebugLagrangeTables<E> = (
    Vec<<E as Pairing>::G1>,
    Vec<<E as Pairing>::G1>,
    Vec<<E as Pairing>::G1>,
    Vec<<E as Pairing>::G1>,
    usize,
    usize,
);

#[doc(hidden)]
pub fn debug_lagrange_tables<E, C>(
    accumulator: &Accumulator<E>,
    circuit: C,
) -> Result<DebugLagrangeTables<E>, BridgeError>
where
    E: Pairing<ScalarField = ark_bn254::Fr, BaseField = ark_bn254::Fq>,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();
    cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
    circuit
        .generate_constraints(cs.clone())
        .map_err(BridgeError::Synthesis)?;
    cs.finalize();
    let matrices = cs.to_matrices().ok_or(BridgeError::DomainTooSmall)?;
    let num_constraints = matrices.num_constraints;
    let num_instance_variables = matrices.num_instance_variables;
    let num_witness_variables = matrices.num_witness_variables;
    let qap_num_variables = (num_instance_variables - 1) + num_witness_variables;

    let domain =
        Radix2EvaluationDomain::<E::ScalarField>::new(num_constraints + num_instance_variables)
            .ok_or(BridgeError::DomainTooSmall)?;
    let domain_size = domain.size();

    let tau_lagrange_g1: Vec<E::G1> = domain.ifft(
        &accumulator.tau_powers_g1[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );
    let alpha_lagrange_g1: Vec<E::G1> = domain.ifft(
        &accumulator.alpha_tau_powers_g1[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );
    let beta_lagrange_g1: Vec<E::G1> = domain.ifft(
        &accumulator.beta_tau_powers_g1[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );

    let mut a_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    let mut c_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    a_lagrange[..num_instance_variables].copy_from_slice(
        &tau_lagrange_g1[num_constraints..(num_instance_variables + num_constraints)],
    );
    accumulate_matrix(&matrices.a, &tau_lagrange_g1, &mut a_lagrange);
    accumulate_matrix(&matrices.c, &tau_lagrange_g1, &mut c_lagrange);

    // Only `a` (and `beta_a_lagrange`, its beta-weighted counterpart) gets
    // the instance-consistency prefill — `b`/`alpha_b_lagrange` must NOT,
    // matching the reference exactly (see the matching note in
    // `from_phase1` below, where this exact bug was found and fixed).
    let mut beta_a_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    let mut alpha_b_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    beta_a_lagrange[..num_instance_variables].copy_from_slice(
        &beta_lagrange_g1[num_constraints..(num_instance_variables + num_constraints)],
    );
    accumulate_matrix(&matrices.a, &beta_lagrange_g1, &mut beta_a_lagrange);
    accumulate_matrix(&matrices.b, &alpha_lagrange_g1, &mut alpha_b_lagrange);

    Ok((
        a_lagrange,
        c_lagrange,
        beta_a_lagrange,
        alpha_b_lagrange,
        num_constraints,
        num_instance_variables,
    ))
}

/// Assembles a `delta = 1` starting `ProvingKey` for `circuit` from real
/// Phase 1 output — replacing `MPCParameters::new_placeholder`'s local
/// alpha/beta/gamma sampling with values that actually came from (a local
/// run of, for now — see `docs/CEREMONY.md`) the Phase 1 ceremony above.
/// `gamma` is fixed at `1` (so `vk.gamma_g2` is the plain generator),
/// matching both this reference construction and how `delta` starts —
/// confirmed against the reference: BGM17 doesn't ceremony-randomize
/// gamma at all, only delta (in Phase 2) and tau/alpha/beta (in Phase 1).
pub fn from_phase1<E, C>(
    accumulator: &Accumulator<E>,
    circuit: C,
) -> Result<ProvingKey<E>, BridgeError>
where
    E: Pairing<ScalarField = ark_bn254::Fr, BaseField = ark_bn254::Fq>,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();
    cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
    circuit
        .generate_constraints(cs.clone())
        .map_err(BridgeError::Synthesis)?;
    cs.finalize();
    let matrices = cs.to_matrices().ok_or(BridgeError::DomainTooSmall)?;

    let num_constraints = matrices.num_constraints;
    let num_instance_variables = matrices.num_instance_variables;
    let num_witness_variables = matrices.num_witness_variables;
    let qap_num_variables = (num_instance_variables - 1) + num_witness_variables;

    let domain =
        Radix2EvaluationDomain::<E::ScalarField>::new(num_constraints + num_instance_variables)
            .ok_or(BridgeError::DomainTooSmall)?;
    let domain_size = domain.size();

    if accumulator.tau_powers_g2.len() < domain_size
        || accumulator.tau_powers_g1.len() < 2 * domain_size - 1
    {
        return Err(BridgeError::AccumulatorTooSmall {
            needed: domain_size,
            have: accumulator.tau_powers_g2.len(),
        });
    }

    // Lagrange-basis coefficients (evaluated at the ceremony's secret
    // tau, via the accumulated curve points — never the scalar itself),
    // via an inverse FFT over curve points. `ark_poly`'s FFT domain is
    // generic over anything implementing `DomainCoeff`, which curve group
    // elements satisfy — confirmed with an isolated cross-check against
    // direct scalar-field polynomial evaluation before writing this.
    let tau_lagrange_g1: Vec<E::G1> = domain.ifft(
        &accumulator.tau_powers_g1[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );
    let tau_lagrange_g2: Vec<E::G2> = domain.ifft(
        &accumulator.tau_powers_g2[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );
    let alpha_lagrange_g1: Vec<E::G1> = domain.ifft(
        &accumulator.alpha_tau_powers_g1[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );
    let beta_lagrange_g1: Vec<E::G1> = domain.ifft(
        &accumulator.beta_tau_powers_g1[..domain_size]
            .iter()
            .map(|p| p.into_group())
            .collect::<Vec<_>>(),
    );

    // Matches `LibsnarkReduction::instance_map_with_evaluation` exactly:
    // qap_num_variables+1 slots (index 0 is the implicit "one" instance
    // variable), with the first num_instance_variables slots seeded from
    // the domain positions *beyond* the real constraints (the
    // instance-consistency block), then every real constraint's
    // contribution added on top.
    let mut a_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    let mut b_lagrange_g1 = vec![E::G1::zero(); qap_num_variables + 1];
    let mut b_lagrange_g2 = vec![E::G2::zero(); qap_num_variables + 1];
    let mut c_lagrange = vec![E::G1::zero(); qap_num_variables + 1];

    a_lagrange[..num_instance_variables].copy_from_slice(
        &tau_lagrange_g1[num_constraints..(num_instance_variables + num_constraints)],
    );

    accumulate_matrix(&matrices.a, &tau_lagrange_g1, &mut a_lagrange);
    accumulate_matrix(&matrices.b, &tau_lagrange_g1, &mut b_lagrange_g1);
    accumulate_matrix(&matrices.b, &tau_lagrange_g2, &mut b_lagrange_g2);
    accumulate_matrix(&matrices.c, &tau_lagrange_g1, &mut c_lagrange);

    // ext[i] = beta*A_i(tau) + alpha*B_i(tau) + C_i(tau) — the standard
    // Groth16 numerator shared by both the public (gamma_abc) and private
    // (l_query) terms; which one a given index belongs to is purely a
    // matter of where it falls in `0..=qap_num_variables`.
    //
    // Since alpha/beta only exist here as curve points (`E::G1`), not
    // scalars, "beta * A_i(tau)" is computed as a *pairing-free* trick:
    // replay A_i's *matrix coefficients* against `beta_lagrange_g1`
    // (which already has an extra factor of beta baked in per Lagrange
    // slot) the same way `a_lagrange` was built from `tau_lagrange_g1`.
    //
    // IMPORTANT, found via a direct cross-check against
    // `LibsnarkReduction`'s own scalar output (which caught this exactly
    // — see `docs/CEREMONY.md`'s recorded-bug note): only `a`
    // (`beta_a_lagrange` here) gets the instance-consistency prefill
    // below. `b` does NOT — confirmed against the reference, which has
    // exactly one `copy_from_slice` call, targeting only `a[start..end]`.
    // An earlier version of this function incorrectly also prefilled
    // `alpha_b_lagrange`, which silently produced a ProvingKey whose
    // gamma_abc_g1/l_query entries were wrong in a way self-consistency
    // checks alone never would have caught — only a proof round-trip (or
    // this direct scalar cross-check) surfaces it.
    let mut beta_a_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    let mut alpha_b_lagrange = vec![E::G1::zero(); qap_num_variables + 1];
    beta_a_lagrange[..num_instance_variables].copy_from_slice(
        &beta_lagrange_g1[num_constraints..(num_instance_variables + num_constraints)],
    );
    accumulate_matrix(&matrices.a, &beta_lagrange_g1, &mut beta_a_lagrange);
    accumulate_matrix(&matrices.b, &alpha_lagrange_g1, &mut alpha_b_lagrange);

    let mut ext = vec![E::G1::zero(); qap_num_variables + 1];
    for i in 0..=qap_num_variables {
        ext[i] = beta_a_lagrange[i] + alpha_b_lagrange[i] + c_lagrange[i];
    }

    let gamma_abc_g1: Vec<E::G1Affine> = ext[..num_instance_variables]
        .iter()
        .map(|p| p.into_affine())
        .collect();
    let l_query: Vec<E::G1Affine> = ext[num_instance_variables..]
        .iter()
        .map(|p| p.into_affine())
        .collect();

    let a_query: Vec<E::G1Affine> = a_lagrange.iter().map(|p| p.into_affine()).collect();
    let b_g1_query: Vec<E::G1Affine> = b_lagrange_g1.iter().map(|p| p.into_affine()).collect();
    let b_g2_query: Vec<E::G2Affine> = b_lagrange_g2.iter().map(|p| p.into_affine()).collect();

    // H-query: (tau^i * (tau^m - 1)) * G1 for i in 0..domain_size-1,
    // computed via the algebraic identity tau^(i+m)*(tau^m-1)/(tau^m-1)
    // == tau^(i+m) - tau^i (so no division needed) — same identity
    // celo-org's `h_query_groth16` uses, valid for any Radix2 domain
    // regardless of its size, so it carries over correctly once fed the
    // domain size arkworks actually uses (`domain_size`, not celo-org's
    // possibly-different assumption).
    let h_query: Vec<E::G1Affine> = (0..domain_size - 1)
        .map(|i| {
            let a: E::G1 = accumulator.tau_powers_g1[i + domain_size].into_group();
            let b: E::G1 = accumulator.tau_powers_g1[i].into_group();
            (a - b).into_affine()
        })
        .collect();

    let alpha_g1 = accumulator.alpha_tau_powers_g1[0];
    let beta_g1 = accumulator.beta_tau_powers_g1[0];
    let beta_g2 = accumulator.beta_g2;
    let delta_g1 = E::G1Affine::generator();
    let delta_g2 = E::G2Affine::generator();
    let gamma_g2 = E::G2Affine::generator();

    Ok(ProvingKey {
        vk: VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        },
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    })
}

/// Replays a sparse R1CS matrix's (coefficient, variable_index) entries
/// against a Lagrange-coefficient table indexed by constraint number,
/// accumulating into `out[variable_index]`. Generic over the group (used
/// for both G1 and G2 Lagrange tables — `b_g2_query` needs the G2 form).
/// This is the curve-point analogue of `LibsnarkReduction`'s scalar
/// accumulation loop (`a[index] += u_i * coeff`), just with group-element
/// scalar multiplication instead of field multiplication.
fn accumulate_matrix<F, G>(matrix: &ark_relations::r1cs::Matrix<F>, lagrange: &[G], out: &mut [G])
where
    F: ark_ff::PrimeField,
    G: std::ops::Mul<F, Output = G> + Copy + std::ops::AddAssign,
{
    for (constraint_idx, row) in matrix.iter().enumerate() {
        for (coeff, var_idx) in row {
            out[*var_idx] += lagrange[constraint_idx] * *coeff;
        }
    }
}
