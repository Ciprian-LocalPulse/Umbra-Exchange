# Architecture

## Components

```
┌─────────────────┐        ┌──────────────────────┐        ┌─────────────────┐
│  Contributor     │        │   Umbra Relay         │        │  Consumer /      │
│  (SOC / OSINT    │──────▶│   (public, stateless  │──────▶│  SOC tooling      │
│  researcher)     │ proofs │   proof aggregator)    │ feed  │  (via STIX/MISP)  │
└─────────────────┘        └──────────────────────┘        └─────────────────┘
        │                              │
        │ local, never leaves device   │ only proofs + commitments,
        │ - raw IOC feed               │ never raw indicators or
        │ - credential secret key      │ contributor identity
        └──────────────────────────────┘
```

### 1. Contributor client

Runs entirely on the contributor's side. Holds:
- the raw IOC feed (never transmitted)
- an anonymous contributor credential (issued once, reusable, unlinkable across submissions — see `PROTOCOL_SPEC.md §2`)

Produces, per epoch:
- a Merkle root committing to the set of IOCs observed this epoch
- a Groth16 proof of "I hold a valid tier-N credential AND this root commits to a set containing IOC X" for any IOC the contributor chooses to make provable
- publishes only the root + proof + a nullifier (to prevent double-counting), never the underlying set

### 2. Umbra Relay

A dumb, stateless (or minimally stateful) public service. It:
- verifies proofs (cheap — verification is the fast side of Groth16)
- aggregates per-IOC observation counts and tier-weighted reputation scores
- never sees raw IOCs from contributors who choose not to disclose them, only commitments and proofs
- exposes a query API: "what's the aggregate confidence on indicator X" and "give me the current STIX bundle of indicators above confidence threshold T"

Relay nodes can be run by anyone — there is no single trusted hub. Multiple relays can cross-verify each other's aggregate outputs, since verification is public and cheap.

### 3. Consumer

Any SOC/SIEM/EDR that can ingest STIX 2.1 or a MISP feed. Consumes the relay's output like any other threat-intel feed. No ZK-specific tooling required on this side — this is the whole point.

## Design principles

- **The verifier should never need to trust the relay operator.** Proofs are checked client-side by anyone who wants to; the relay is a convenience cache, not a root of trust.
- **Disclosure is opt-in per indicator, not per feed.** A contributor can prove membership for specific IOCs (e.g. ones they're comfortable naming) while keeping the rest of their feed's existence private — the Merkle commitment covers the whole epoch's set, but only disclosed leaves are ever opened.
- **Sybil resistance without identity.** Tiering is enforced by the credential issuance process (who gets a tier-3 credential and how), not by linking submissions to a persistent identity. This is a policy question as much as a cryptographic one — see open issue in `THREAT_MODEL.md`.

## What's built vs. designed (Phase 0 honesty)

| Component | Status |
|---|---|
| Reputation aggregation (`reputation-accumulator`) | **implemented and tested** — tier-weighted scoring, replay rejection via nullifier set, `cargo test -p reputation-accumulator` passes (7/7) |
| Merkle-inclusion circuit (`proof-of-observation`) | public/witness input allocation **compiles and is verified against real arkworks 0.4 crates**; leaf hashing, Merkle path folding, credential gadget, and nullifier constraint are still TODO in `src/lib.rs` — allocating inputs is not the same as constraining them, see the comment in that file |
| Credential/tiering scheme | designed, not implemented |
| Relay service | not started — `reputation-accumulator`'s interface is ready to be consumed by one |
| STIX/MISP schema mapping | draft in `schema/` |

Everything marked "compiles"/"tested" above was actually run in a sandboxed build, not asserted from memory — see `docs/BUILD_NOTES.md` for the toolchain quirks that mattered.
