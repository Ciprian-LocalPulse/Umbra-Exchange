//! Two-party private set intersection (DH-PSI), for README point 3:
//! "check whether an indicator is in someone else's private list without
//! either party revealing their full list to the other."
//!
//! ## Why Ristretto255, not BN254/arkworks
//!
//! Everything else in this workspace uses arkworks over BN254, but this
//! crate deliberately doesn't. DH-PSI needs to map each item to a group
//! element via a "hash-to-group" step whose discrete log (relative to
//! whatever base point) is NOT efficiently computable by anyone —
//! otherwise the protocol's whole security collapses. Concretely: if you
//! hash an item to a *scalar* `m` and then compute `m * G` for a public
//! generator `G` (a tempting shortcut — arkworks doesn't ship a
//! hash-to-curve config for BN254's G1, see below), the protocol reduces
//! to blinding via modular multiplication, and modular multiplication has
//! a trivially computable inverse. A party who receives `a * H(x)` (an
//! honest participant's supposedly-hidden blinded query) could recover
//! `a * G` from any *one* item whose preimage they can guess (which is
//! common for indicators — IPs, common domain names), and from there
//! forge blinded queries for arbitrary other items without ever
//! interacting with the real querier again — completely defeating the
//! blinding. This was checked and rejected during design, not assumed
//! safe.
//!
//! A proper defense needs an actual hash-to-curve construction (RFC 9380
//! style). `ark-ec` does ship one (`ark_ec::hashing`), but only Simplified
//! SWU and Wahby-Boneh maps, both of which require curve-specific isogeny
//! parameters — and neither `ark-bn254` nor this workspace has ever
//! derived them for BN254's G1 (checked directly against both crates'
//! source before starting this crate). Deriving isogeny parameters by
//! hand is exactly the kind of "unreviewed cryptographic cleverness"
//! `SECURITY.md` warns against, so this crate uses `curve25519-dalek`'s
//! Ristretto group instead, whose `RistrettoPoint::hash_from_bytes` is a
//! standard, widely-audited (Signal and many others depend on this
//! exact crate) hash-to-group primitive that doesn't require deriving
//! anything. The tradeoff is a second elliptic-curve dependency in the
//! workspace instead of reusing BN254 everywhere; that's the right side
//! of the tradeoff here — this protocol has no reason to be
//! SNARK-compatible in the first place (nothing here is proven inside a
//! circuit), so there's no cost to using a different, better-suited curve.
//!
//! ## Protocol (semi-honest / passive security only)
//!
//! Roles: a **Holder** with a private set (e.g. a SOC's blocklist), and a
//! **Querier** who wants to know if one item is in it.
//!
//! 1. Holder picks an ephemeral secret scalar `b` ([`HolderKey`]) and
//!    computes [`blind_set`]: `{ b * H(s) : s in S }`, shuffled, sent to
//!    the Querier once (reusable for many subsequent queries under the
//!    same `b` — see "What this leaks" below for the cost of reuse).
//! 2. Querier picks an ephemeral secret scalar `a` ([`QuerierKey`]) and
//!    calls [`blind_query`] on their item `x`, sending `a * H(x)` to the
//!    Holder.
//! 3. Holder calls [`respond_to_query`], returning `b * (a * H(x)) = ab *
//!    H(x)`.
//! 4. Querier calls [`finish_query`], removing their own blinding
//!    (`a^{-1} * (ab * H(x)) = b * H(x)`) and checking that value against
//!    the blinded set from step 1: present iff `x` was in `S`.
//!
//! Neither side ever sees the other's raw items or raw secret scalar.
//!
//! ## What this leaks (read before deploying)
//!
//! This is the semi-honest DH-PSI baseline — it does NOT defend against a
//! participant who actively deviates from the protocol (e.g. a Holder who
//! answers with garbage to see how the Querier reacts, or reports "not
//! found" regardless of the true answer). Beyond that:
//! - **Set size**: the Holder's blinded set has a length; `|S|` is not
//!   hidden.
//! - **Cross-query linkability under a reused Holder key**: if the same
//!   `HolderKey` is used across multiple Queriers, two Queriers who
//!   happen to query the *same* item and compare their own unblinded
//!   results (`b * H(x)`) will find them identical — they can detect they
//!   queried the same item, without the Holder's help. Rotate
//!   `HolderKey` per relationship/epoch if this matters for a deployment.
//! - **Guessable item universe**: like `proof_of_observation::indicator`,
//!   this doesn't hide items whose value is guessable/enumerable (a
//!   Querier can just query every candidate IP in a /24, for instance).
//!   This is inherent to PSI/PMT over a small or structured item space,
//!   not specific to this implementation.
//!
//! None of this is unusual for DH-PSI — it's the standard baseline this
//! entire protocol family accepts — but it's exactly the kind of caveat
//! that's easy to lose track of once code exists, so it's stated here
//! rather than only in a design doc.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use proof_of_observation::indicator::normalize_indicator;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum PsiError {
    /// A peer sent bytes that don't decode to a valid Ristretto point —
    /// either corruption in transit or an actively malicious peer. Either
    /// way, refuse rather than guess.
    InvalidPoint,
}

impl std::fmt::Display for PsiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsiError::InvalidPoint => write!(f, "received bytes do not decode to a valid point"),
        }
    }
}

impl std::error::Error for PsiError {}

/// Hashes a raw indicator string to a Ristretto group element. Reuses
/// `proof_of_observation::indicator::normalize_indicator` so the same
/// indicator string is treated as "the same identity" across both this
/// crate and the proof-of-observation circuit, even though the two
/// hash-to-*-something steps target different algebraic structures (a
/// BN254 scalar there, a Ristretto point here) for different reasons —
/// see that module's own docs for the normalization's current
/// (deliberately conservative) limits.
fn hash_indicator(raw: &str) -> RistrettoPoint {
    let normalized = normalize_indicator(raw);
    RistrettoPoint::hash_from_bytes::<Sha512>(normalized.as_bytes())
}

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// A Holder's ephemeral secret blinding scalar. Not `Debug`/`Display` on
/// purpose (avoid accidental logging of a secret), and zeroized on drop —
/// same care this workspace already takes with `credential_secret`
/// elsewhere, applied here since this is exactly the kind of value that
/// must never leak.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct HolderKey(Scalar);

impl HolderKey {
    /// Generates a fresh, random key. Callers should generate a new one
    /// per relationship/epoch rather than reusing one indefinitely — see
    /// module docs on cross-query linkability under key reuse.
    pub fn generate() -> Self {
        Self(random_scalar())
    }
}

/// A Querier's ephemeral secret blinding scalar for one query. Generate a
/// fresh one per query — see [`blind_query`].
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct QuerierKey(Scalar);

/// Step 1 (Holder side): blinds and shuffles the Holder's private set for
/// one-time transmission to a Querier. The shuffle is not optional — an
/// unshuffled blinded set would leak the original set's ordering (e.g.
/// insertion order) to the Querier, which this function's caller
/// shouldn't have to remember to prevent.
pub fn blind_set(key: &HolderKey, raw_items: &[String]) -> Vec<CompressedRistretto> {
    let mut blinded: Vec<CompressedRistretto> = raw_items
        .iter()
        .map(|item| (key.0 * hash_indicator(item)).compress())
        .collect();

    // Fisher-Yates, using OsRng directly rather than pulling in a shuffle
    // helper for one use site.
    let mut rng = OsRng;
    for i in (1..blinded.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        blinded.swap(i, j);
    }
    blinded
}

/// Step 2 (Querier side): blinds one query item with a fresh ephemeral
/// key. Returns the key (needed later to unblind the Holder's response —
/// see [`finish_query`]) and the blinded query to send to the Holder.
/// Generating a fresh key per call (rather than reusing one across
/// queries) is what keeps separate queries for the *same* item
/// unlinkable from each other by anyone who only sees the wire traffic.
pub fn blind_query(raw_item: &str) -> (QuerierKey, CompressedRistretto) {
    let key = QuerierKey(random_scalar());
    let blinded = (key.0 * hash_indicator(raw_item)).compress();
    (key, blinded)
}

/// Step 3 (Holder side): double-blinds a Querier's already-blinded query.
/// Returns an error rather than panicking if `blinded_query` isn't a
/// valid point — a Querier (or a network fault) supplying garbage here
/// shouldn't be able to crash the Holder's process.
pub fn respond_to_query(
    key: &HolderKey,
    blinded_query: CompressedRistretto,
) -> Result<CompressedRistretto, PsiError> {
    let point = blinded_query.decompress().ok_or(PsiError::InvalidPoint)?;
    Ok((key.0 * point).compress())
}

/// A Holder's blinded set (from [`blind_set`]), indexed once for O(1)
/// membership checks in [`finish_query`] instead of an O(|S|) linear scan
/// per query — matters once a Querier is checking many items against the
/// same received set.
pub struct BlindedSet {
    // CompressedRistretto doesn't implement Hash, but its underlying
    // bytes do — index on those instead.
    present: HashMap<[u8; 32], ()>,
}

impl BlindedSet {
    pub fn new(points: &[CompressedRistretto]) -> Self {
        Self {
            present: points.iter().map(|p| (p.to_bytes(), ())).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.present.len()
    }

    pub fn is_empty(&self) -> bool {
        self.present.is_empty()
    }
}

/// Step 4 (Querier side): removes the Querier's own blinding from the
/// Holder's double-blinded response and checks the result against the
/// Holder's blinded set. Returns `Ok(true)` iff the originally-queried
/// item is in the Holder's set.
pub fn finish_query(
    key: QuerierKey,
    double_blinded: CompressedRistretto,
    blinded_set: &BlindedSet,
) -> Result<bool, PsiError> {
    let point = double_blinded.decompress().ok_or(PsiError::InvalidPoint)?;
    // Scalar::invert() panics on a zero scalar; random_scalar() has
    // probability ~2^-252 of producing zero, low enough that this isn't
    // worth a fallible API for, but worth naming why it's safe here.
    let unblinded = (key.0.invert() * point).compress();
    Ok(blinded_set.present.contains_key(&unblinded.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_in_set_is_found() {
        let holder_key = HolderKey::generate();
        let set = vec!["evil.example".to_string(), "also-evil.example".to_string()];
        let blinded_set = BlindedSet::new(&blind_set(&holder_key, &set));

        let (querier_key, blinded_query) = blind_query("evil.example");
        let response = respond_to_query(&holder_key, blinded_query).unwrap();
        let found = finish_query(querier_key, response, &blinded_set).unwrap();

        assert!(found, "an item actually in the Holder's set must be found");
    }

    #[test]
    fn item_not_in_set_is_not_found() {
        let holder_key = HolderKey::generate();
        let set = vec!["evil.example".to_string()];
        let blinded_set = BlindedSet::new(&blind_set(&holder_key, &set));

        let (querier_key, blinded_query) = blind_query("benign.example");
        let response = respond_to_query(&holder_key, blinded_query).unwrap();
        let found = finish_query(querier_key, response, &blinded_set).unwrap();

        assert!(!found, "an item not in the Holder's set must not be found");
    }

    #[test]
    fn empty_set_never_matches_and_does_not_panic() {
        let holder_key = HolderKey::generate();
        let blinded_set = BlindedSet::new(&blind_set(&holder_key, &[]));
        assert!(blinded_set.is_empty());

        let (querier_key, blinded_query) = blind_query("anything.example");
        let response = respond_to_query(&holder_key, blinded_query).unwrap();
        let found = finish_query(querier_key, response, &blinded_set).unwrap();

        assert!(!found);
    }

    #[test]
    fn same_item_hashes_to_the_same_point_deterministically() {
        // Required for the protocol to work at all: the Holder and
        // Querier independently hash the same raw string and must land on
        // the same underlying point before any blinding is applied.
        assert_eq!(
            super::hash_indicator("evil.example"),
            super::hash_indicator("evil.example")
        );
    }

    #[test]
    fn repeated_queries_for_the_same_item_are_unlinkable_on_the_wire() {
        // Each call to blind_query uses a fresh random scalar, so the
        // wire-visible blinded query differs every time even for the
        // identical underlying item.
        let (_, q1) = blind_query("evil.example");
        let (_, q2) = blind_query("evil.example");
        assert_ne!(
            q1, q2,
            "two blindings of the same item must not be linkable on the wire"
        );
    }

    #[test]
    fn corrupted_wire_bytes_are_rejected_not_panicking() {
        let holder_key = HolderKey::generate();
        // All-0xFF fails Ristretto's canonicity/field checks on
        // decompression — a realistic stand-in for corrupted-in-transit
        // or maliciously-crafted wire bytes. The property under test is
        // "this returns Err, it doesn't panic" — this test reaching its
        // final assert already demonstrates the "doesn't panic" half.
        let bytes = [0xFFu8; 32];
        let garbage = CompressedRistretto::from_slice(&bytes)
            .expect("from_slice only checks length, not validity");
        let result = respond_to_query(&holder_key, garbage);
        assert!(matches!(result, Err(PsiError::InvalidPoint)));
    }

    #[test]
    fn colluding_queriers_can_detect_matching_queries_under_a_reused_holder_key() {
        // Documents, concretely, the linkability caveat from the module
        // docs rather than only asserting it in prose: two different
        // Queriers who both query the same item against the same
        // HolderKey end up with identical unblinded values, and could
        // notice that by comparing notes — even without the Holder's
        // involvement in that comparison.
        let holder_key = HolderKey::generate();

        let (q1_key, q1_blinded) = blind_query("shared-item.example");
        let q1_response = respond_to_query(&holder_key, q1_blinded).unwrap();
        let q1_unblinded = (q1_key.0.invert() * q1_response.decompress().unwrap()).compress();

        let (q2_key, q2_blinded) = blind_query("shared-item.example");
        let q2_response = respond_to_query(&holder_key, q2_blinded).unwrap();
        let q2_unblinded = (q2_key.0.invert() * q2_response.decompress().unwrap()).compress();

        assert_eq!(
            q1_unblinded, q2_unblinded,
            "two queries for the same item under the same HolderKey must be linkable this way — documented, not a bug"
        );
    }

    #[test]
    fn blind_set_output_length_matches_input() {
        let holder_key = HolderKey::generate();
        let set = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let blinded = blind_set(&holder_key, &set);
        assert_eq!(blinded.len(), set.len());
    }
}
