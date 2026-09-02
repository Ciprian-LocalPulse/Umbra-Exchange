//! Shared best-effort indicator-type classification, used by both
//! `stix.rs` and `misp.rs` so the two export formats can't silently
//! disagree about what a given raw indicator "is." See `stix.rs`'s
//! original module docs (now here) for why this stays deliberately
//! narrow: asserting a structured type that's wrong is worse than not
//! asserting one at all.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorKind {
    Md5,
    Sha1,
    Sha256,
    Ipv4,
    Ipv6,
    Url,
    Domain,
    /// Doesn't match any of the above — exported formats should fall back
    /// to a clearly-marked "unrecognized" representation rather than
    /// guessing.
    Unrecognized,
}

pub fn classify(raw_indicator: &str) -> IndicatorKind {
    let s = raw_indicator.trim();

    if is_hex(s, 32) {
        return IndicatorKind::Md5;
    }
    if is_hex(s, 40) {
        return IndicatorKind::Sha1;
    }
    if is_hex(s, 64) {
        return IndicatorKind::Sha256;
    }
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return IndicatorKind::Ipv4;
    }
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return IndicatorKind::Ipv6;
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return IndicatorKind::Url;
    }
    if looks_like_domain(s) {
        return IndicatorKind::Domain;
    }

    IndicatorKind::Unrecognized
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_hashes_by_length() {
        assert_eq!(classify(&"a".repeat(32)), IndicatorKind::Md5);
        assert_eq!(classify(&"a".repeat(40)), IndicatorKind::Sha1);
        assert_eq!(classify(&"a".repeat(64)), IndicatorKind::Sha256);
    }

    #[test]
    fn classifies_ips() {
        assert_eq!(classify("198.51.100.23"), IndicatorKind::Ipv4);
        assert_eq!(classify("2001:db8::1"), IndicatorKind::Ipv6);
    }

    #[test]
    fn classifies_url_and_domain() {
        assert_eq!(classify("https://evil.example/payload"), IndicatorKind::Url);
        assert_eq!(classify("evil.example"), IndicatorKind::Domain);
    }

    #[test]
    fn classifies_unrecognized() {
        assert_eq!(
            classify("!!! not an indicator ###"),
            IndicatorKind::Unrecognized
        );
    }
}
