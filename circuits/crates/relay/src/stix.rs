//! STIX 2.1 export — see `schema/stix_mapping.md` for the field mapping
//! this implements, and its "Explicit non-mapping" section for why
//! undisclosed indicators (ones the relay only ever saw as an opaque
//! `indicator_hash`, never as a raw string) simply don't appear here.

use serde::Serialize;
use serde_json::{json, Value};

/// Best-effort STIX 2.1 pattern construction from a raw, disclosed
/// indicator string. Covers the common IOC types explicitly (hashes,
/// IPv4, IPv6, domains, URLs); anything else gets a clearly-marked
/// fallback rather than a guessed-and-possibly-wrong structured pattern —
/// asserting `[domain-name:value = '...']` for something that isn't
/// actually a domain would be worse than not asserting a type at all.
pub fn stix_pattern_for(raw_indicator: &str) -> String {
    let s = raw_indicator.trim();

    if is_hex(s, 32) {
        return format!("[file:hashes.MD5 = '{s}']");
    }
    if is_hex(s, 40) {
        return format!("[file:hashes.'SHA-1' = '{s}']");
    }
    if is_hex(s, 64) {
        return format!("[file:hashes.'SHA-256' = '{s}']");
    }
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return format!("[ipv4-addr:value = '{s}']");
    }
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[ipv6-addr:value = '{s}']");
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        let escaped = s.replace('\'', "\\'");
        return format!("[url:value = '{escaped}']");
    }
    if looks_like_domain(s) {
        let escaped = s.replace('\'', "\\'");
        return format!("[domain-name:value = '{escaped}']");
    }

    // Unrecognized shape: don't guess a STIX object type we can't back up.
    let escaped = s.replace('\'', "\\'");
    format!("[x-umbra:unrecognized-indicator = '{escaped}']")
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Deliberately simple: no scheme/slash, at least one dot, and every
/// label is a plausible DNS label (alphanumeric plus hyphen). Good enough
/// to separate "evil.example" from "not a domain at all"; not a full DNS
/// grammar and not meant to be one — see module docs on normalization
/// limitations in `proof_of_observation::indicator`.
fn looks_like_domain(s: &str) -> bool {
    if s.contains('/') || s.contains(' ') || !s.contains('.') {
        return false;
    }
    s.split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

/// One epoch's default validity window, per `docs/PROTOCOL_SPEC.md`
/// ("Epoch: a fixed time window (default: 24h)"). `epoch` here is parsed
/// as a `YYYYMMDD` integer, matching how every prover/test/demo tool in
/// this workspace actually constructs epoch values today — note this is a
/// stronger assumption than `docs/PROTOCOL_SPEC.md`'s own parenthetical
/// example ("Unix day number"), which is a smaller integer; that
/// inconsistency between the spec text and this codebase's de facto
/// convention should get reconciled explicitly rather than silently
/// picked one way forever. Returns `(valid_from, valid_until)` as RFC
/// 3339 UTC timestamps, or `None` if `epoch` doesn't parse as `YYYYMMDD`.
pub fn epoch_validity_window(epoch: u64) -> Option<(String, String)> {
    let year = epoch / 10_000;
    let month = (epoch / 100) % 100;
    let day = epoch % 100;
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day > days_in_month {
        return None;
    }

    let valid_from = format!("{year:04}-{month:02}-{day:02}T00:00:00Z");

    let (next_year, next_month, next_day) = if day < days_in_month {
        (year, month, day + 1)
    } else if month < 12 {
        (year, month + 1, 1)
    } else {
        (year + 1, 1, 1)
    };
    let valid_until = format!("{next_year:04}-{next_month:02}-{next_day:02}T00:00:00Z");

    Some((valid_from, valid_until))
}

/// Raw score -> STIX `confidence` (0-100). Deliberately a relay-config
/// parameter (per `schema/stix_mapping.md`: "mapping from raw weighted
/// score is a relay config parameter") rather than a fixed formula: a
/// simple clamped linear scale, `min(100, score * 100 / score_for_full_confidence)`.
pub fn normalize_confidence(score: u32, score_for_full_confidence: u32) -> u8 {
    if score_for_full_confidence == 0 {
        return 100; // avoid div-by-zero; a zero threshold means "anything is full confidence"
    }
    let scaled = (score as u64 * 100) / score_for_full_confidence as u64;
    scaled.min(100) as u8
}

#[derive(Debug, Clone)]
pub struct StixIndicatorInput {
    pub raw_indicator: String,
    pub epoch: u64,
    pub score: u32,
    pub proof_count: u32,
}

#[derive(Debug, Serialize)]
pub struct StixBundle {
    pub id: String,
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub objects: Vec<Value>,
}

/// Builds a STIX 2.1 Bundle of `indicator` SDOs from already-disclosed,
/// already-scored observations. Callers (the relay's export handler)
/// are responsible for having already filtered to disclosed indicators
/// crossing the confidence threshold — this function just does the field
/// mapping in `schema/stix_mapping.md`, it doesn't apply policy.
pub fn build_stix_bundle(
    inputs: &[StixIndicatorInput],
    score_for_full_confidence: u32,
    relay_id: &str,
) -> StixBundle {
    let objects = inputs
        .iter()
        .enumerate()
        .filter_map(|(i, input)| {
            let (valid_from, valid_until) = epoch_validity_window(input.epoch)?;
            Some(json!({
                "type": "indicator",
                // Deterministic per (relay_id, indicator, epoch) rather
                // than random, so re-exporting the same data twice
                // produces the same STIX object id.
                "id": format!("indicator--{}", deterministic_uuid_like(relay_id, &input.raw_indicator, input.epoch, i)),
                "spec_version": "2.1",
                "pattern": stix_pattern_for(&input.raw_indicator),
                "pattern_type": "stix",
                "valid_from": valid_from,
                "valid_until": valid_until,
                "confidence": normalize_confidence(input.score, score_for_full_confidence),
                "x_umbra_proof_count": input.proof_count,
                "x_umbra_relay_id": relay_id,
            }))
        })
        .collect();

    StixBundle {
        id: format!(
            "bundle--{}",
            deterministic_uuid_like(relay_id, "bundle", 0, 0)
        ),
        bundle_type: "bundle".to_string(),
        objects,
    }
}

/// Not a real UUID (no external crate for this yet) — a deterministic,
/// UUID-*shaped* hex string derived from its inputs via a simple FNV-1a
/// hash, repeated to fill 128 bits. Good enough to give STIX objects
/// stable, collision-unlikely-in-practice ids without pulling in a new
/// dependency for this alone; swap for a real UUIDv5 (namespace-based,
/// which is the STIX-recommended approach for deterministic ids) if this
/// relay grows enough surface area to justify the `uuid` crate elsewhere
/// too.
fn deterministic_uuid_like(relay_id: &str, key: &str, epoch: u64, salt: usize) -> String {
    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
    let input = format!("{relay_id}|{key}|{epoch}|{salt}");
    let h1 = fnv1a(input.as_bytes());
    let h2 = fnv1a(format!("{input}|2").as_bytes());
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (h1 >> 32) as u32,
        (h1 >> 16) as u16,
        (h1 as u16) & 0x0fff | 0x4000,
        (h2 >> 48) as u16 & 0x3fff | 0x8000,
        h2 & 0xffff_ffff_ffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_for_sha256() {
        let hash = "a".repeat(64);
        assert_eq!(
            stix_pattern_for(&hash),
            format!("[file:hashes.'SHA-256' = '{hash}']")
        );
    }

    #[test]
    fn pattern_for_md5() {
        let hash = "b".repeat(32);
        assert_eq!(
            stix_pattern_for(&hash),
            format!("[file:hashes.MD5 = '{hash}']")
        );
    }

    #[test]
    fn pattern_for_ipv4() {
        assert_eq!(
            stix_pattern_for("198.51.100.23"),
            "[ipv4-addr:value = '198.51.100.23']"
        );
    }

    #[test]
    fn pattern_for_domain() {
        assert_eq!(
            stix_pattern_for("evil.example"),
            "[domain-name:value = 'evil.example']"
        );
    }

    #[test]
    fn pattern_for_url() {
        assert_eq!(
            stix_pattern_for("https://evil.example/payload"),
            "[url:value = 'https://evil.example/payload']"
        );
    }

    #[test]
    fn pattern_for_unrecognized_does_not_claim_a_type() {
        let pattern = stix_pattern_for("!!! not an indicator at all ###");
        assert!(pattern.contains("x-umbra:unrecognized-indicator"));
    }

    #[test]
    fn epoch_validity_window_for_normal_date() {
        let (from, until) = epoch_validity_window(20260822).unwrap();
        assert_eq!(from, "2026-08-22T00:00:00Z");
        assert_eq!(until, "2026-08-23T00:00:00Z");
    }

    #[test]
    fn epoch_validity_window_rolls_over_month_end() {
        let (from, until) = epoch_validity_window(20260831).unwrap();
        assert_eq!(from, "2026-08-31T00:00:00Z");
        assert_eq!(until, "2026-09-01T00:00:00Z");
    }

    #[test]
    fn epoch_validity_window_rolls_over_year_end() {
        let (from, until) = epoch_validity_window(20261231).unwrap();
        assert_eq!(from, "2026-12-31T00:00:00Z");
        assert_eq!(until, "2027-01-01T00:00:00Z");
    }

    #[test]
    fn epoch_validity_window_handles_leap_day() {
        let (from, until) = epoch_validity_window(20240228).unwrap();
        assert_eq!(from, "2024-02-28T00:00:00Z");
        assert_eq!(until, "2024-02-29T00:00:00Z"); // 2024 is a leap year
    }

    #[test]
    fn epoch_validity_window_rejects_invalid_dates() {
        assert!(epoch_validity_window(20260231).is_none()); // Feb 31 doesn't exist
        assert!(epoch_validity_window(20261301).is_none()); // month 13
        assert!(epoch_validity_window(0).is_none());
    }

    #[test]
    fn confidence_scales_and_clamps() {
        assert_eq!(normalize_confidence(0, 10), 0);
        assert_eq!(normalize_confidence(5, 10), 50);
        assert_eq!(normalize_confidence(10, 10), 100);
        assert_eq!(
            normalize_confidence(50, 10),
            100,
            "must clamp, not overflow past 100"
        );
    }

    #[test]
    fn build_bundle_skips_entries_with_unparseable_epochs() {
        let inputs = vec![
            StixIndicatorInput {
                raw_indicator: "evil.example".to_string(),
                epoch: 20260822,
                score: 5,
                proof_count: 3,
            },
            StixIndicatorInput {
                raw_indicator: "also-evil.example".to_string(),
                epoch: 99999999, // not a valid YYYYMMDD date
                score: 5,
                proof_count: 1,
            },
        ];
        let bundle = build_stix_bundle(&inputs, 10, "test-relay");
        assert_eq!(
            bundle.objects.len(),
            1,
            "the unparseable-epoch entry must be skipped, not panic"
        );
        assert_eq!(
            bundle.objects[0]["pattern"],
            "[domain-name:value = 'evil.example']"
        );
    }

    #[test]
    fn bundle_ids_are_deterministic() {
        let inputs = vec![StixIndicatorInput {
            raw_indicator: "evil.example".to_string(),
            epoch: 20260822,
            score: 5,
            proof_count: 3,
        }];
        let a = build_stix_bundle(&inputs, 10, "test-relay");
        let b = build_stix_bundle(&inputs, 10, "test-relay");
        assert_eq!(
            a.objects[0]["id"], b.objects[0]["id"],
            "re-exporting the same data must produce the same STIX object id"
        );
    }
}
