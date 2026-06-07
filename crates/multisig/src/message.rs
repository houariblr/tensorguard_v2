/// Canonical encoding of attestation data for signing.
/// ALL daemons must sign the IDENTICAL byte sequence.
///
/// Layout (55 bytes):
///   pool[0..32]           — pool pubkey
///   nonce[32..40]         — u64 little-endian
///   verdict[40]           — 0=Safe, 1=Attack
///   confidence_bps[41..43]— u16 little-endian
///   lyapunov_x100[43..47] — u32 little-endian
///   kolmogorov_x100[47..51]─ u32 little-endian
///   ricci_x100[51..55]    — u32 little-endian
pub fn encode_attestation(
    pool:            &[u8; 32],
    nonce:           u64,
    verdict:         u8,
    confidence_bps:  u16,
    lyapunov_x100:   u32,
    kolmogorov_x100: u32,
    ricci_x100:      u32,
) -> [u8; 55] {
    let mut msg = [0u8; 55];
    msg[0..32].copy_from_slice(pool);
    msg[32..40].copy_from_slice(&nonce.to_le_bytes());
    msg[40] = verdict;
    msg[41..43].copy_from_slice(&confidence_bps.to_le_bytes());
    msg[43..47].copy_from_slice(&lyapunov_x100.to_le_bytes());
    msg[47..51].copy_from_slice(&kolmogorov_x100.to_le_bytes());
    msg[51..55].copy_from_slice(&ricci_x100.to_le_bytes());
    msg
}
