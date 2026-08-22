# Contributing

This project is Phase 0 — the protocol design is more settled than the code. The most valuable contributions right now are:

1. **Critique of `docs/PROTOCOL_SPEC.md` and `docs/THREAT_MODEL.md`.** Especially the open questions: credential issuance governance, Sybil resistance on tier-0, and the timing-correlation caveat. If you've worked on MISP/OpenCTI/ISAC sharing in practice, your operational experience is worth more here than more cryptography.
2. **Filling in the circuit TODOs** in `circuits/crates/proof-of-observation/src/lib.rs` — Merkle path gadget, Poseidon leaf hashing, nullifier constraint. Please open an issue describing your approach before a large PR; the circuit needs to stay auditable, not just functional.
3. **A relay reference implementation.** Nothing exists yet. Even a minimal HTTP service that verifies proofs and does naive in-memory aggregation would move this forward a lot.
4. **MISP object template review**, if you run MISP day to day — see the open question in `schema/stix_mapping.md`.

## Ground rules

- No PR that silently weakens a security property to make tests pass. If a shortcut is genuinely necessary for Phase 0, document it loudly in `THREAT_MODEL.md`, don't bury it.
- Cite sources for cryptographic claims where it's not obvious (arkworks docs, papers, etc.) — this is a security-sensitive project and unreviewed cleverness is a liability, not a feature.
- Discuss significant design changes in an issue before a PR — the protocol spec is meant to be a stable reference, not something that drifts silently.
