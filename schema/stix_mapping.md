# STIX 2.1 export mapping (draft)

Indicators that cross the configured confidence threshold get exported from the relay as STIX 2.1 `indicator` SDOs so any existing SOC/TIP tooling can consume them without touching the ZK layer at all.

| Umbra field | STIX 2.1 field | Notes |
|---|---|---|
| `indicator` (disclosed value) | `pattern` | wrapped in the appropriate STIX pattern, e.g. `[file:hashes.SHA256 = '...']` |
| `confidence(X, E)` | `confidence` | normalized 0–100; mapping from raw weighted score is a relay config parameter |
| epoch window | `valid_from` / `valid_until` | one epoch's worth of validity by default; consumers can extend via their own TIP policy |
| n/a | `x_umbra_proof_count` | custom property: number of distinct valid proofs behind this score, for analyst transparency |
| n/a | `x_umbra_relay_id` | which relay produced this bundle, for provenance when cross-checking against other relays |

## MISP

Same underlying data, exported as a MISP event with one attribute per disclosed indicator, `to_ids` set based on the confidence threshold, and the proof-count/relay-id as MISP object attributes rather than STIX custom properties. Exact object template TBD — open to input from anyone who actually runs a MISP instance day to day, since template conventions vary a lot by community.

## Explicit non-mapping

Undisclosed indicators (ones covered only by a Merkle root, never opened) have no STIX/MISP representation at all — by design, since they were never meant to leave the ZK layer as raw values.
