use frost_ed25519::{self as frost, keys::*, round1, round2};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

pub struct Round1Output {
    pub nonces:      round1::SigningNonces,
    pub commitments: round1::SigningCommitments,
}

pub struct Round2Output {
    pub signature_share: round2::SignatureShare,
}

pub struct AggregatedSignature {
    /// 64-byte standard Ed25519 signature
    pub bytes: [u8; 64],
    /// 32-byte group public key for on-chain verification
    pub group_pubkey: [u8; 32],
}

// ── Round 1 ──────────────────────────────────────────────────────────────────

pub fn round1_commit(key_package: &KeyPackage) -> Round1Output {
    let mut rng = OsRng;
    let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);
    Round1Output { nonces, commitments }
}

// ── Round 2 ──────────────────────────────────────────────────────────────────

pub fn round2_sign(
    key_package:     &KeyPackage,
    nonces:          &round1::SigningNonces,
    message:         &[u8],
    // no doc comment on parameter — Rust doesn't allow it
    commitments_map: &BTreeMap<frost::Identifier, round1::SigningCommitments>,
) -> Result<Round2Output, frost::Error> {
    let signing_package = frost::SigningPackage::new(commitments_map.clone(), message);
    let sig_share = round2::sign(&signing_package, nonces, key_package)?;
    Ok(Round2Output { signature_share: sig_share })
}

// ── Aggregation ───────────────────────────────────────────────────────────────

pub fn aggregate(
    message:          &[u8],
    commitments_map:  &BTreeMap<frost::Identifier, round1::SigningCommitments>,
    signature_shares: &BTreeMap<frost::Identifier, round2::SignatureShare>,
    pubkey_package:   &PublicKeyPackage,
) -> Result<AggregatedSignature, frost::Error> {
    let signing_package = frost::SigningPackage::new(commitments_map.clone(), message);
    let signature = frost::aggregate(&signing_package, signature_shares, pubkey_package)?;

    // serialize() returns Result<Vec<u8>> in frost 2.x
    let sig_vec: Vec<u8> = signature.serialize()?;
    let sig_bytes: [u8; 64] = sig_vec
        .try_into()
        .expect("Ed25519 signature is always 64 bytes");

    let pk_vec: Vec<u8> = pubkey_package.verifying_key().serialize()?;
    let group_pubkey: [u8; 32] = pk_vec
        .try_into()
        .expect("Ed25519 pubkey is always 32 bytes");

    Ok(AggregatedSignature { bytes: sig_bytes, group_pubkey })
}

// ── Verification ─────────────────────────────────────────────────────────────

pub fn verify_aggregated(
    message:        &[u8],
    sig_bytes:      &[u8; 64],
    group_pk_bytes: &[u8; 32],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let Ok(vk) = VerifyingKey::from_bytes(group_pk_bytes) else { return false };

    // ed25519-dalek 2.x: from_bytes returns Signature directly (not Result)
    let sig = Signature::from_bytes(sig_bytes);

    vk.verify(message, &sig).is_ok()
}
