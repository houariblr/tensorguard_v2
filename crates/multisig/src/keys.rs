use frost_ed25519::{self as frost, keys::*};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

pub struct KeygenResult {
    /// 32-byte Ed25519 group public key — store on-chain in GuardConfig
    pub group_pubkey: [u8; 32],
    /// One package per daemon — never share between nodes
    pub key_packages: BTreeMap<frost::Identifier, KeyPackage>,
    /// Public verification data — safe to share
    pub pubkey_package: PublicKeyPackage,
}

pub fn generate_key_shares(
    threshold:   u16,
    num_signers: u16,
) -> Result<KeygenResult, frost::Error> {
    let mut rng = OsRng;

    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        num_signers,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let key_packages: BTreeMap<frost::Identifier, KeyPackage> = shares
        .into_iter()
        .map(|(id, share)| KeyPackage::try_from(share).map(|kp| (id, kp)))
        .collect::<Result<_, _>>()?;

    // serialize() returns Result<Vec<u8>> in frost 2.x — unwrap the Vec first
    let pk_vec: Vec<u8> = pubkey_package
        .verifying_key()
        .serialize()?;

    let group_pubkey: [u8; 32] = pk_vec
        .try_into()
        .expect("Ed25519 pubkey is always 32 bytes");

    Ok(KeygenResult { group_pubkey, key_packages, pubkey_package })
}
