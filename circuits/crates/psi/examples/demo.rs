//! Single-process simulation of both sides of a DH-PSI exchange — the
//! Holder and Querier would normally be two different organizations
//! talking over a network, but the cryptographic core doesn't care, and
//! this is the simplest way to see the whole flow work end to end.
//!
//! Run with: `cargo run -p psi --example demo`

use psi::{blind_query, blind_set, finish_query, respond_to_query, BlindedSet, HolderKey};

fn main() {
    // --- Holder side: has a private blocklist, never sends it in the clear.
    let holder_blocklist = vec![
        "malicious-c2.example".to_string(),
        "phishing-site.example".to_string(),
        "evil.example".to_string(),
    ];
    let holder_key = HolderKey::generate();
    let blinded_set_wire = blind_set(&holder_key, &holder_blocklist);
    println!(
        "Holder: blinded {} item(s), sending blinded (not raw) values to Querier.",
        blinded_set_wire.len()
    );
    let blinded_set = BlindedSet::new(&blinded_set_wire);

    // --- Querier side: wants to know if specific indicators are on the
    // Holder's blocklist, without revealing which indicators it's asking
    // about (beyond what blinding allows) and without seeing the rest of
    // the Holder's list.
    for candidate in ["evil.example", "benign.example", "malicious-c2.example"] {
        let (querier_key, blinded_query) = blind_query(candidate);
        println!("Querier: asking about '{candidate}' (sent only as a blinded point).");

        // --- Holder side: double-blinds without ever learning `candidate`.
        let response = respond_to_query(&holder_key, blinded_query)
            .expect("a well-formed blinded query always decompresses");

        // --- Querier side: unblinds and checks membership locally.
        let found = finish_query(querier_key, response, &blinded_set)
            .expect("a well-formed response always decompresses");

        println!(
            "Querier: '{candidate}' is {}on the Holder's blocklist.\n",
            if found { "" } else { "NOT " }
        );
    }
}
