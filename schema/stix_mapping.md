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

**Implemented** in `relay::misp` (`GET /v1/export/misp?threshold=N&to_ids_confidence_threshold=M`), reusing the same shared indicator-type classification (`relay::indicator_kind`) the STIX export uses, so the two formats can't silently disagree about what a given raw indicator "is."

Same underlying data as STIX export, structured as a MISP event containing one custom MISP Object (`umbra-observation`) per disclosed indicator: the indicator itself (type/category from `indicator_kind`, e.g. `sha256`/"Payload delivery", `domain`/"Network activity"), plus `proof-count` and `relay-id` as sibling attributes within that same Object — MISP's real Object mechanism, not STIX-style custom properties, per this doc's original design note. `to_ids` is set when the indicator's normalized confidence (same `score_for_full_confidence` scale as STIX) crosses `to_ids_confidence_threshold` (default 50).

**Important caveat, stated plainly**: `umbra-observation` is a project-defined custom Object, not one registered in MISP's community object-template repository (github.com/MISP/misp-objects). Building a properly community-reviewed template needs input from people who actually run MISP instances day to day — this doc's original "Not yet implemented" note about needing that input still applies to *template standardization*, even though the export itself now works and produces valid MISP JSON.

## Explicit non-mapping

Undisclosed indicators (ones covered only by a Merkle root, never opened) have no STIX/MISP representation at all — by design, since they were never meant to leave the ZK layer as raw values. Enforced in code: `export_stix`'s handler only ever includes indicator_hashes present in `Inner::disclosed_indicators`, which is populated exclusively by the verified-disclosure path above.
