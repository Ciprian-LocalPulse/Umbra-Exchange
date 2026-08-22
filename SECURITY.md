# Security Policy

Umbra Exchange is a Phase 0 research prototype implementing zero-knowledge
cryptography (Groth16 circuits, Poseidon hashing, Merkle-inclusion proofs).
**Nothing in this repository has been independently audited.** Treat every
proof, key, and circuit produced by this codebase as unsound against a
motivated adversary until stated otherwise — see `docs/THREAT_MODEL.md` for
the current, explicit list of what is and isn't protected against.

Given that, security reports are taken seriously even at this early stage:
a flaw found now, before there are real users or deployed relays, is far
cheaper to fix than one found later.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security
vulnerability, including (but not limited to):

- a soundness or completeness bug in either circuit (`proof-of-observation`,
  `reputation-accumulator`) that would let a prover cheat, forge a
  nullifier, or bypass Merkle-inclusion;
- a flaw in the Poseidon parameter provenance or usage
  (`circuits/crates/proof-of-observation/src/poseidon_params.rs`);
- any way to deanonymize a contributor from public proof/aggregate data
  beyond what `docs/THREAT_MODEL.md` already discloses;
- a memory-safety or supply-chain issue in a dependency that materially
  affects this project.

Instead, email **security@localpulse.pro** (or contact@localpulse.pro if
the security alias bounces) with:

1. A description of the issue and its potential impact.
2. Steps to reproduce, or a minimal proof-of-concept circuit/test.
3. Which crate/commit you tested against.

You should get an acknowledgement within a few days — this is currently a
small, part-time-maintained project, so please be patient. Once a report is
confirmed, a fix will be prioritized and you'll be credited (unless you'd
rather stay anonymous) when it ships.

## Scope

In scope:
- `circuits/crates/proof-of-observation`
- `circuits/crates/reputation-accumulator`
- protocol design as specified in `docs/PROTOCOL_SPEC.md`

Explicitly out of scope (already tracked as known, open problems — see
`docs/THREAT_MODEL.md` — no need to report these unless you have a concrete
mitigation or a way to make the impact worse than currently understood):
- the credential-tier claim being unenforced (`min_tier` is an
  unconstrained public input as of this writing);
- the lack of a real multi-party trusted-setup ceremony;
- timing/volume correlation at the relay layer;
- availability/DDoS resistance of relay nodes.

## Trusted setup and key hygiene

The Groth16 proving/verifying keys generated in this repo's test suite
(`circuit_specific_setup` with a locally-generated key) are for testing
only. Never reuse a locally-generated proving key outside of tests, and
never treat a proof produced with one as sound against a party who could
have retained the toxic waste from that local setup.
