//! MISP event export — see `schema/stix_mapping.md`'s "MISP" section.
//!
//! Unlike the STIX export, this does NOT claim conformance with an
//! official MISP community object template (the ones registered at
//! github.com/MISP/misp-objects) — building one of those properly needs
//! input from people who actually run MISP instances day to day, which
//! `schema/stix_mapping.md` explicitly flags as still open. What this
//! implements instead is a reasonable, clearly-labeled custom MISP Object
//! (`umbra-observation`) grouping the indicator attribute with its
//! proof-count/relay-id provenance — using MISP's real, standard Object
//! mechanism (attributes grouped under a named template), just not a
//! template anyone else has agreed to yet. Treat the exact attribute/
//! object names as provisional.

use crate::indicator_kind::{classify, IndicatorKind};
use crate::stix::{epoch_validity_window, normalize_confidence, StixIndicatorInput};
use serde_json::{json, Value};

/// MISP attribute `type` and `category` for a given indicator, via the
/// shared classification in `indicator_kind.rs`. Categories match MISP's
/// own default taxonomy conventions (hashes -> "Payload delivery",
/// network-observable indicators -> "Network activity").
fn misp_type_and_category(kind: IndicatorKind) -> (&'static str, &'static str) {
    match kind {
        IndicatorKind::Md5 => ("md5", "Payload delivery"),
        IndicatorKind::Sha1 => ("sha1", "Payload delivery"),
        IndicatorKind::Sha256 => ("sha256", "Payload delivery"),
        IndicatorKind::Ipv4 => ("ip-dst", "Network activity"),
        IndicatorKind::Ipv6 => ("ip-dst", "Network activity"),
        IndicatorKind::Url => ("url", "Network activity"),
        IndicatorKind::Domain => ("domain", "Network activity"),
        // MISP has a generic "text" type for exactly this case — better
        // than asserting a structured type we can't back up.
        IndicatorKind::Unrecognized => ("text", "Other"),
    }
}

/// Whether an attribute should be marked `to_ids` (i.e. "confident enough
/// to use for automated intrusion-detection matching, not just analyst
/// review"). A relay-config threshold, same spirit as
/// `stix::normalize_confidence`'s `score_for_full_confidence` — kept as a
/// *confidence* (0-100) threshold rather than a raw-score one, so it
/// composes with whatever scale a deployment already chose for STIX
/// export instead of introducing a second, inconsistent scale.
pub fn to_ids_for_confidence(confidence: u8, to_ids_confidence_threshold: u8) -> bool {
    confidence >= to_ids_confidence_threshold
}

/// Builds a MISP event JSON document from already-disclosed,
/// already-scored observations — the same input shape `build_stix_bundle`
/// takes, since both exports describe the same underlying data. Callers
/// are responsible for having already filtered to disclosed indicators
/// crossing whatever score threshold they want; this function does field
/// mapping and policy (the `to_ids` decision), not filtering.
pub fn build_misp_event(
    inputs: &[StixIndicatorInput],
    score_for_full_confidence: u32,
    to_ids_confidence_threshold: u8,
    relay_id: &str,
    event_info: &str,
) -> Value {
    let attributes: Vec<Value> = inputs
        .iter()
        .filter_map(|input| {
            let (date, _) = epoch_validity_window(input.epoch)?;
            let confidence = normalize_confidence(input.score, score_for_full_confidence);
            let kind = classify(&input.raw_indicator);
            let (misp_type, category) = misp_type_and_category(kind);
            let to_ids = to_ids_for_confidence(confidence, to_ids_confidence_threshold);

            Some(json!({
                "type": "Object",
                "name": "umbra-observation",
                "meta-category": "network",
                "description": "One Umbra Exchange disclosed indicator, with its zero-knowledge-verified provenance.",
                "Attribute": [
                    {
                        "type": misp_type,
                        "category": category,
                        "value": input.raw_indicator,
                        "to_ids": to_ids,
                        "comment": format!("confidence {confidence}/100"),
                    },
                    {
                        "type": "counter",
                        "category": "Other",
                        "object_relation": "proof-count",
                        "value": input.proof_count.to_string(),
                        "to_ids": false,
                    },
                    {
                        "type": "text",
                        "category": "Other",
                        "object_relation": "relay-id",
                        "value": relay_id,
                        "to_ids": false,
                    },
                ],
                // `date` from epoch_validity_window is already a full
                // RFC 3339 timestamp ("2026-08-22T00:00:00Z"), not a bare
                // date — use it directly. An earlier version of this
                // wrapped it in another format!("{date}T00:00:00Z"),
                // producing a doubled-up "...T00:00:00ZT00:00:00Z"
                // timestamp; caught by running the live end-to-end demo,
                // not by the unit tests above (none of which asserted on
                // this exact field's value).
                "first_seen": date,
            }))
        })
        .collect();

    json!({
        "Event": {
            "info": event_info,
            "threat_level_id": "3", // MISP's "Undefined" level — this relay doesn't assess threat severity, only confidence
            "analysis": "0", // "Initial" — this is raw, automated ZK-verified output, not analyst-reviewed
            "distribution": "0", // "Your organisation only" — a safe, conservative default; deployments should set this deliberately
            "date": inputs
                .first()
                .and_then(|i| epoch_validity_window(i.epoch))
                .map(|(date, _)| date.split('T').next().unwrap_or_default().to_string())
                .unwrap_or_default(),
            "Object": attributes,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_ids_respects_threshold() {
        assert!(to_ids_for_confidence(80, 50));
        assert!(to_ids_for_confidence(50, 50));
        assert!(!to_ids_for_confidence(49, 50));
    }

    #[test]
    fn misp_type_for_common_kinds() {
        assert_eq!(misp_type_and_category(IndicatorKind::Sha256).0, "sha256");
        assert_eq!(misp_type_and_category(IndicatorKind::Domain).0, "domain");
        assert_eq!(misp_type_and_category(IndicatorKind::Ipv4).0, "ip-dst");
        assert_eq!(
            misp_type_and_category(IndicatorKind::Unrecognized).0,
            "text"
        );
    }

    #[test]
    fn build_event_includes_disclosed_indicators() {
        let inputs = vec![StixIndicatorInput {
            raw_indicator: "evil.example".to_string(),
            epoch: 20260822,
            score: 8,
            proof_count: 4,
        }];
        let event = build_misp_event(&inputs, 10, 50, "test-relay", "Umbra Exchange export");

        let objects = event["Event"]["Object"].as_array().unwrap();
        assert_eq!(objects.len(), 1);
        let attrs = objects[0]["Attribute"].as_array().unwrap();
        assert_eq!(attrs[0]["type"], "domain");
        assert_eq!(attrs[0]["value"], "evil.example");
        assert_eq!(
            attrs[0]["to_ids"], true,
            "confidence 80 must cross a 50 threshold"
        );
        assert_eq!(attrs[1]["value"], "4");
        assert_eq!(attrs[2]["value"], "test-relay");
        // Regression test: an earlier version double-appended the time
        // suffix here ("...T00:00:00ZT00:00:00Z") since
        // epoch_validity_window already returns a full RFC 3339
        // timestamp, not a bare date — caught via a live demo, not by a
        // unit test, since no test asserted this field's exact value
        // until now.
        assert_eq!(objects[0]["first_seen"], "2026-08-22T00:00:00Z");
    }

    #[test]
    fn low_confidence_indicator_is_not_marked_to_ids() {
        let inputs = vec![StixIndicatorInput {
            raw_indicator: "maybe-evil.example".to_string(),
            epoch: 20260822,
            score: 1,
            proof_count: 1,
        }];
        let event = build_misp_event(&inputs, 10, 50, "test-relay", "Umbra Exchange export");
        let objects = event["Event"]["Object"].as_array().unwrap();
        let attrs = objects[0]["Attribute"].as_array().unwrap();
        assert_eq!(
            attrs[0]["to_ids"], false,
            "confidence 10 must not cross a 50 threshold"
        );
    }

    #[test]
    fn skips_entries_with_unparseable_epochs() {
        let inputs = vec![
            StixIndicatorInput {
                raw_indicator: "evil.example".to_string(),
                epoch: 20260822,
                score: 5,
                proof_count: 1,
            },
            StixIndicatorInput {
                raw_indicator: "also-evil.example".to_string(),
                epoch: 99999999,
                score: 5,
                proof_count: 1,
            },
        ];
        let event = build_misp_event(&inputs, 10, 50, "test-relay", "Umbra Exchange export");
        let objects = event["Event"]["Object"].as_array().unwrap();
        assert_eq!(
            objects.len(),
            1,
            "the unparseable-epoch entry must be skipped, not panic"
        );
    }
}
