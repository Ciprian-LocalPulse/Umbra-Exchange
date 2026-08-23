# STIX 2.1 export mapping

Indicators that cross the configured confidence threshold get exported from the relay as STIX 2.1 `indicator` SDOs so any existing SOC/TIP tooling can consume them without touching the ZK layer at all.

**Implemented in `relay::stix`** (`GET /v1/export/stix?threshold=N`), as of the disclosure-and-export work landing alongside the credential-tier gadget.

| Umbra field | STIX 2.1 field | Notes |
|---|---|---|
| `indicator` (disclosed value) | `pattern` | Best-effort type detection: file hashes (MD5/SHA-1/SHA-256 by hex length), IPv4/IPv6, URLs (`http(s)://` prefix), domains (dotted, no slash/space). Anything else exports as `[x-umbra:unrecognized-indicator = '...']` rather than a guessed-and-possibly-wrong structured type — see `stix::stix_pattern_for`. |
| `confidence(X, E)` | `confidence` | normalized 0–100 via `stix::normalize_confidence`; the raw-score-to-100 scale is `AppState::score_for_full_confidence`, a relay config parameter (default 10) |
| epoch window | `valid_from` / `valid_until` | one epoch's worth of validity (24h), computed by `stix::epoch_validity_window`. **Note:** this parses `epoch` as a `YYYYMMDD` integer, matching how every prover/tool in this workspace actually constructs epoch values today — which is a stronger assumption than this doc's own historical "Unix day number" phrasing implied. That inconsistency should get explicitly reconciled (pick one, update the other) rather than left as a latent trap. |
| n/a | `x_umbra_proof_count` | custom property: number of distinct valid proofs behind this score, for analyst transparency |
| n/a | `x_umbra_relay_id` | which relay produced this bundle (`AppState::relay_id`), for provenance when cross-checking against other relays |

## Disclosure is a separate, verified step

`indicator_hash` alone (an opaque field element) can't be turned into a STIX `pattern` — STIX needs the raw string. A contributor optionally includes the raw indicator in `SubmitObservationRequest::indicator`; the relay checks it actually hashes (via `proof_of_observation::indicator::indicator_hash_from_raw`, a Poseidon-based hash over the normalized string — see that module's docs for why, and for the current normalization limits: trim+lowercase only, no defanging/URL-canonicalization yet) to the same `indicator_hash` the proof verified against, and rejects the *entire* submission on mismatch. This is what stops anyone from attaching an arbitrary STIX pattern to someone else's valid proof. Disclosure is monotonic (recorded once, never retracted by a later non-disclosing submission of the same indicator_hash) and is what "crossing into STIX export eligibility" actually means, independent of score.

## MISP

Same underlying data, exported as a MISP event with one attribute per disclosed indicator, `to_ids` set based on the confidence threshold, and the proof-count/relay-id as MISP object attributes rather than STIX custom properties. **Not yet implemented** — exact object template TBD, open to input from anyone who actually runs a MISP instance day to day, since template conventions vary a lot by community.

## Explicit non-mapping

Undisclosed indicators (ones covered only by a Merkle root, never opened) have no STIX/MISP representation at all — by design, since they were never meant to leave the ZK layer as raw values. Enforced in code: `export_stix`'s handler only ever includes indicator_hashes present in `Inner::disclosed_indicators`, which is populated exclusively by the verified-disclosure path above.
