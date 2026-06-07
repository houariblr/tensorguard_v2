pub mod keys;
pub mod protocol;
pub mod message;

pub use keys::{generate_key_shares, KeygenResult};
pub use protocol::{
    round1_commit, round2_sign, aggregate,
    verify_aggregated, AggregatedSignature,
    Round1Output, Round2Output,
};
pub use message::encode_attestation;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use frost_ed25519::Identifier;

    #[test]
    fn test_full_frost_protocol_2_of_3() {
        // ── Setup ──────────────────────────────────────────────────────────
        let keygen = generate_key_shares(2, 3).expect("keygen failed");
        let identifiers: Vec<Identifier> = keygen.key_packages.keys().cloned().collect();

        // Pick daemons 0 and 1 (2 of 3)
        let id_a = identifiers[0];
        let id_b = identifiers[1];
        let kp_a = &keygen.key_packages[&id_a];
        let kp_b = &keygen.key_packages[&id_b];

        // ── Message ────────────────────────────────────────────────────────
        let msg = encode_attestation(&[0xABu8; 32], 42, 0, 7880, 10880, 43693, 110);

        // ── Round 1 ────────────────────────────────────────────────────────
        let r1_a = round1_commit(kp_a);
        let r1_b = round1_commit(kp_b);

        let mut commitments = BTreeMap::new();
        commitments.insert(id_a, r1_a.commitments);
        commitments.insert(id_b, r1_b.commitments);

        // ── Round 2 ────────────────────────────────────────────────────────
        let r2_a = round2_sign(kp_a, &r1_a.nonces, &msg, &commitments)
            .expect("round2 sign A failed");
        let r2_b = round2_sign(kp_b, &r1_b.nonces, &msg, &commitments)
            .expect("round2 sign B failed");

        let mut shares = BTreeMap::new();
        shares.insert(id_a, r2_a.signature_share);
        shares.insert(id_b, r2_b.signature_share);

        // ── Aggregate ──────────────────────────────────────────────────────
        let agg = aggregate(&msg, &commitments, &shares, &keygen.pubkey_package)
            .expect("aggregation failed");

        // ── Verify ─────────────────────────────────────────────────────────
        assert!(
            verify_aggregated(&msg, &agg.bytes, &agg.group_pubkey),
            "aggregated signature verification failed"
        );

        // Signature must be standard Ed25519 (64 bytes)
        assert_eq!(agg.bytes.len(), 64);
        assert_eq!(agg.group_pubkey.len(), 32);

        println!("✅ FROST 2/3 protocol: OK");
        println!("   sig:  {} bytes", agg.bytes.len());
        println!("   pk:   {} bytes", agg.group_pubkey.len());
    }

    #[test]
    fn test_wrong_message_fails() {
        let keygen  = generate_key_shares(2, 2).expect("keygen failed");
        let ids: Vec<_> = keygen.key_packages.keys().cloned().collect();
        let kp_a = &keygen.key_packages[&ids[0]];
        let kp_b = &keygen.key_packages[&ids[1]];

        let msg = encode_attestation(&[1u8; 32], 1, 0, 5000, 100, 200, 100);

        let r1_a = round1_commit(kp_a);
        let r1_b = round1_commit(kp_b);

        let mut comms = BTreeMap::new();
        comms.insert(ids[0], r1_a.commitments);
        comms.insert(ids[1], r1_b.commitments);

        let r2_a = round2_sign(kp_a, &r1_a.nonces, &msg, &comms).unwrap();
        let r2_b = round2_sign(kp_b, &r1_b.nonces, &msg, &comms).unwrap();

        let mut shares = BTreeMap::new();
        shares.insert(ids[0], r2_a.signature_share);
        shares.insert(ids[1], r2_b.signature_share);

        let agg = aggregate(&msg, &comms, &shares, &keygen.pubkey_package).unwrap();

        // Different message → verification fails
        let wrong_msg = encode_attestation(&[2u8; 32], 99, 1, 9999, 999, 999, 999);
        assert!(!verify_aggregated(&wrong_msg, &agg.bytes, &agg.group_pubkey));

        println!("✅ Wrong message rejection: OK");
    }
}
