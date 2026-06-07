use anchor_lang::prelude::*;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum Verdict {
    Safe,
    Attack,
}

/// One vote from a single daemon node
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Vote {
    pub signer:          Pubkey,
    pub verdict:         Verdict,
    pub confidence_bps:  u16,
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,
}

/// Replaces the old Attestation — accumulates votes until threshold
/// Seeds: ["vote_account", pool, &nonce.to_le_bytes()]
#[account]
pub struct VoteAccount {
    pub pool:      Pubkey,
    pub nonce:     u64,
    pub slot:      u64,

    /// Votes received so far (max = signers.len())
    pub votes:     Vec<Vote>,

    /// True once votes >= threshold and verdict is decided
    pub finalized: bool,

    /// Set when finalized — majority verdict
    pub verdict:         Verdict,
    pub confidence_bps:  u16,

    /// Averaged metrics across all votes
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,

    pub bump: u8,
}

impl VoteAccount {
    /// Max signers we support (fixed for space calculation)
    pub const MAX_SIGNERS: usize = 5;

    /// Space: discriminator(8) + pool(32) + nonce(8) + slot(8)
    /// + votes: 4 + MAX_SIGNERS*(32+1+2+4+4+4) = 4 + 5*47 = 239
    /// + finalized(1) + verdict(1) + confidence(2) + metrics(12) + bump(1) = 272
    pub const LEN: usize = 8 + 32 + 8 + 8 + 239 + 1 + 1 + 2 + 12 + 1;

    pub const MAX_AGE_SLOTS: u64 = 40;

    /// Compute majority verdict and average metrics from votes
    pub fn finalize(&mut self) {
        let attack_votes = self.votes.iter()
            .filter(|v| v.verdict == Verdict::Attack)
            .count();

        self.verdict = if attack_votes * 2 >= self.votes.len() {
            Verdict::Attack
        } else {
            Verdict::Safe
        };

        let n = self.votes.len() as u64;
        self.confidence_bps  = (self.votes.iter().map(|v| v.confidence_bps  as u64).sum::<u64>() / n) as u16;
        self.lyapunov_x100   = (self.votes.iter().map(|v| v.lyapunov_x100   as u64).sum::<u64>() / n) as u32;
        self.kolmogorov_x100 = (self.votes.iter().map(|v| v.kolmogorov_x100 as u64).sum::<u64>() / n) as u32;
        self.ricci_x100      = (self.votes.iter().map(|v| v.ricci_x100      as u64).sum::<u64>() / n) as u32;

        self.finalized = true;
    }
}

/// Global config — now stores N trusted signers + threshold M
/// Seeds: ["guard_config", authority]
#[account]
pub struct GuardConfig {
    pub authority:      Pubkey,

    /// All trusted daemon pubkeys (up to MAX_SIGNERS)
    pub signers:        Vec<Pubkey>,

    /// Minimum votes needed to finalize an attestation (M of N)
    pub threshold:      u8,

    /// FROST group public key
    pub group_pubkey:   [u8; 32],

    pub active:         bool,
    pub bump:           u8,
}

impl GuardConfig {
    /// space: discriminator(8) + authority(32)
    /// + signers: 4 + MAX*32(160) + threshold(1) + active(1) + bump(1) = 207
    pub const LEN: usize = 8 + 32 + 4 + (VoteAccount::MAX_SIGNERS * 32) + 1 + 32 + 1 + 1;

    pub fn is_trusted(&self, key: &Pubkey) -> bool {
        self.signers.contains(key)
    }
}

/// Tracks daemon liveness per pool.
/// Seeds: ["pool_guard_state", pool]
#[account]
pub struct PoolGuardState {
    pub pool: Pubkey,

    /// Last slot a daemon posted any vote for this pool
    pub last_daemon_activity_slot: u64,

    /// Last slot guard_verify passed (for analytics)
    pub last_verified_slot: u64,

    /// How many times fallback mode was triggered
    pub fallback_count: u64,

    pub bump: u8,
}

impl PoolGuardState {
    pub const LEN: usize = 8 + 32 + 8 + 8 + 8 + 1;

    /// If daemon has been silent for this many slots → fallback mode
    /// ~200 slots ≈ 80 seconds on Solana
    pub const MAX_DAEMON_SILENCE_SLOTS: u64 = 200;

    pub fn daemon_alive(&self, current_slot: u64) -> bool {
        current_slot.saturating_sub(self.last_daemon_activity_slot)
            < Self::MAX_DAEMON_SILENCE_SLOTS
    }
}

/// Replaces the old VoteAccount for the FROST path.
/// Contains ONE aggregated signature from M daemons instead of M separate votes.
/// Seeds: ["agg_attestation", pool, &nonce.to_le_bytes()]
#[account]
pub struct AggregatedAttestation {
    pub pool:            Pubkey,
    pub nonce:           u64,
    pub slot:            u64,

    pub verdict:         Verdict,
    pub confidence_bps:  u16,
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,

    /// Bitmask: bit i = 1 means signer[i] contributed to this aggregation
    /// e.g. 0b011 = daemons 0 and 1 signed (2/3)
    pub signer_bitmask: u8,

    /// 64-byte Ed25519 aggregated signature (standard — verifiable by Solana ed25519_program)
    pub agg_signature: [u8; 64],

    pub bump: u8,
}

impl AggregatedAttestation {
    /// Space: discriminator(8) + pool(32) + nonce(8) + slot(8)
    /// + verdict(1) + confidence(2) + metrics(12)
    /// + bitmask(1) + sig(96) + bump(1) = 169
    pub const LEN: usize = 8 + 32 + 8 + 8 + 1 + 2 + 12 + 1 + 64 + 1;

    pub const MAX_AGE_SLOTS: u64 = 40;

    /// Count how many daemons contributed (popcount of bitmask)
    pub fn signer_count(&self) -> u8 {
        self.signer_bitmask.count_ones() as u8
    }
}
