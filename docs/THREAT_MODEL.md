# Threat Model

## What Umbra Exchange protects against

- **Relay compromise / relay operator curiosity.** A relay operator (even a malicious one) never sees raw contributor telemetry — only Merkle roots, proofs, and voluntarily-disclosed (indicator, epoch) pairs. Compromising a relay does not deanonymize contributors or leak undisclosed indicators.
- **Feed correlation attacks.** Because credentials are unlinkable across submissions (subject to the caveat below), an observer of the public proof stream cannot trivially cluster submissions by contributor.
- **Score manipulation via replay.** Nullifiers prevent a single contributor from claiming the same observation multiple times within or across epochs to inflate confidence.

## What it does NOT protect against, and known open problems

- **Timing/volume correlation.** If a contributor is the *only* org submitting proofs from a particular network vantage point at a particular time, epoch-level timing could still narrow down who they are. This is a metadata leak inherent to any real-time system and needs mitigation (e.g. batching, submission delay jitter) before this is relied on for high-sensitivity use.
- **Sybil attack on tier-0 credentials.** If tier-0 issuance is fully open (self-registration), an attacker can mint many tier-0 credentials to inflate low-tier confidence scores. Mitigated by tier-weighting (tier 0 contributes little) but not eliminated — this is a policy/rate-limiting problem, not purely cryptographic.
- **Malicious high-tier issuer.** A compromised or malicious tier-3 issuer could mint credentials to a bad actor, who could then poison the feed with false "trusted" observations. Multiple independent issuers reduce blast radius but don't eliminate it. Revocation is unsolved in this draft.
- **Garbage in.** The protocol proves "someone with credential tier N claims to have observed X" — it does not and cannot prove X is actually malicious. Umbra Exchange is a trust/provenance layer, not a detection engine.
- **Trusted setup.** Groth16 requires a trusted setup ceremony per circuit. Until that's run as a proper multi-party ceremony, do not treat proofs from this codebase as sound against a party who could have retained toxic waste from a local setup. The test suite's `groth16_round_trip_local_setup` uses `circuit_specific_setup` with a locally-generated key purely to prove the circuit produces valid Groth16 proofs at all — it is explicitly not a ceremony and the resulting key should never be reused outside tests.
- **Poseidon parameter provenance.** The round constants and MDS matrix used for both the leaf/nullifier hash and the Merkle compression function are the standard circomlib/iden3 "bn254_x5" parameters (generated via the official Poseidon reference script — see `circuits/crates/proof-of-observation/src/poseidon_params.rs` for exact provenance), obtained via the `light-poseidon` crate rather than generated for this project. That's a reasonable, widely-reused trust anchor, but it is not the same thing as this specific circuit having been independently audited.
- **Credential-tier claim IS now cryptographically enforced within the circuit** — `proof-of-observation` constrains `credential_tier >= min_tier` against a credential Merkle tree, see that crate's module-level doc comment. What's *not* solved is upstream of the circuit: the circuit only proves internal consistency relative to whichever `credential_root` the proof names, not that the tree behind that root was honestly issued. A relay is only justified in trusting a tier claim for scoring weight if it separately trusts the specific `credential_root` involved (e.g. via an allowlist of known-issuer roots — see `relay`'s `trusted_credential_roots`); this doesn't change until real issuer governance exists (§2 below still applies in full).

## Non-threats (explicitly out of scope)

- Protecting the confidentiality of an indicator itself once a contributor chooses to disclose it (disclosure is opt-in and, by definition, public afterward).
- Availability/DDoS resistance of relay nodes — treated as a standard infrastructure problem, not a novel one here.
