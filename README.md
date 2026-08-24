# Umbra Exchange

![Umbra Exchange Banner](assets/umbra-exchange-banner.jpg)

**A zero-knowledge threat-intelligence exchange protocol.**  
Prove what you've seen, without showing what you've got.

> **Status:** Early scaffold / research-stage (Phase 0). Not production-ready. Contributions and critique welcome.

## The problem

Threat-intel sharing today runs on trust in a hub. MISP, OpenCTI, ISAC feeds — they all work the same way: you send your raw indicators (IOCs) to a shared instance, and everyone who has access to that instance sees exactly what you saw, when, and (often) who you are.

That's fine for large orgs with legal teams and NDAs. It's a non-starter for:

- small SOCs and independent researchers who don't want to leak their proprietary telemetry to a shared pool
- fraud/OSINT teams whose "blocklist" *is* the business asset
- anyone who wants to contribute to collective defense without becoming a data source for their competitors, or a target once their detection capability is public

The result: most organizations under-share. Collective defense stays weaker than it could be, because the sharing model demands more trust than most participants are willing to extend.

## The idea

Umbra Exchange lets a participant prove statements about their threat telemetry **without revealing the telemetry itself**:

1. **Proof of observation** — "I observed this IOC" without revealing the rest of your feed, using a Merkle-inclusion zk-SNARK. The verifier learns the IOC was seen by *someone with a valid credential*, nothing else.

2. **Anonymous contributor tiering** — a credential (think: anonymous membership proof) that lets you prove "I'm a tier-3 trusted contributor" without linking submissions to your identity across time. This is what keeps the system Sybil-resistant without doxxing anyone.

3. **Private set intersection for blocklists** — check whether an indicator is in someone else's private list without either party revealing their full list to the other.

4. **Aggregate reputation scoring** — a confidence score per IOC, computed from multiple anonymous contributions, without exposing who submitted what.

5. **STIX 2.1 / MISP-compatible I/O** — so existing SOC tooling can consume Umbra output without changing their stack.

## Why this doesn't already exist

There's real academic groundwork — SeCTIS (blockchain + swarm learning), the OPTIMA project, various ZKP-for-digital-identity papers — but nothing that ships as a usable, self-hostable, open-source tool wired for the formats SOC teams actually use (STIX/MISP).

The gap isn't the cryptography — Merkle-inclusion SNARKs and PSI are well-understood primitives — it's that nobody has packaged them for this specific, unglamorous use case and given it away.

## Relationship to Veritas Mesh

The proof engine here is built on the same foundations as [Veritas Mesh](https://github.com/Ciprian-LocalPulse/veritas-mesh) (Groth16 over BN254, arkworks) rather than starting from scratch.

Umbra Exchange is the threat-intel-specific application layer; Veritas Mesh remains the general-purpose compliance/commitment proof engine.

## Repository layout

```text
umbra-exchange/
├── docs/
│   ├── ARCHITECTURE.md       # system design, components, data flow
│   ├── PROTOCOL_SPEC.md      # the actual protocol: message formats, proof statements
│   └── THREAT_MODEL.md       # what this protects against, what it doesn't
├── circuits/                 # Rust workspace, arkworks-based ZK circuits + relay + PSI
│   └── crates/
│       ├── proof-of-observation/
│       ├── reputation-accumulator/
│       ├── relay/             # reference relay: verifies proofs, scores, STIX export
│       └── psi/                # private set intersection for blocklist checks (DH-PSI, Ristretto255 — not arkworks/BN254, see its module docs for why)
├── schema/                   # STIX 2.1 / MISP interop mappings
└── scripts/
```

## Status honestly

Phase 1: the core cryptographic primitives are implemented and tested; governance, real deployment, and hardening are not.

**Implemented and tested:**

- `reputation-accumulator` — aggregate scoring, tier weighting, nullifier-based replay rejection. `cargo test -p reputation-accumulator`: **7/7**.
- `proof-of-observation` — Merkle-inclusion of a disclosed indicator against a published epoch root, nullifier-based double-disclosure prevention, AND a cryptographically-enforced credential-tier gate (a second Merkle tree proves `credential_tier >= min_tier` without revealing which credential or the exact tier). `cargo test -p proof-of-observation --features test-support`: **19/19**.
- `relay` — reference HTTP service: verifies proofs, rejects nullifier replays, aggregates confidence scores, and exports STIX 2.1 bundles for disclosed indicators. `cargo test -p relay`: **20/20**.
- `psi` — two-party private set intersection (DH-PSI over Ristretto255, not arkworks/BN254 — see its module docs for why) for checking one indicator against someone else's private blocklist without either side revealing their full list. `cargo test -p psi`: **8/8**.

Run everything: `cd circuits && cargo test --workspace` — **62/62** as of this writing, `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` both clean.

**Not implemented / explicitly out of scope so far:**

- **Real trusted setup ceremony.** Every Groth16 proving/verifying key in this repo (including `umbra-relay-keygen`'s) comes from a local, single-party, non-ceremony setup. Treat every proof verified against one of these keys as unsound against a party who could have retained that setup's toxic waste — see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
- **Credential issuance governance.** The circuit can prove "this secret is in the credential tree with this tier," but who gets to publish a trustworthy credential tree in the first place is a policy question, not a cryptography one — see [`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md) §2.
- **MISP export**, real network wiring for `psi` (currently a tested library + single-process demo, not yet a second network service), indicator-normalization hardening (defanging, URL/IP canonicalization), and everything else `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md` list as open.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full breakdown and [`docs/BUILD_NOTES.md`](docs/BUILD_NOTES.md) for toolchain notes.

> **Nothing here has been audited. Treat it as a research prototype until this notice is removed.**

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Contributing / support

Issues and PRs welcome — this is meant to be built in the open.

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
