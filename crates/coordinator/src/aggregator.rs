use std::collections::HashMap;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict { Safe, Attack }

/// A single daemon's vote — signature is raw Ed25519 bytes
/// received from the daemon over the network
#[derive(Clone)]
pub struct DaemonVote {
    pub daemon_id:       Pubkey,
    pub verdict:         Verdict,
    pub confidence_bps:  u16,
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,
    /// 64-byte Ed25519 partial signature from FROST round 2
    pub signature:       [u8; 64],
}

/// Final aggregated attestation ready to post on-chain
pub struct AggregatedAttestation {
    pub pool:            Pubkey,
    pub nonce:           u64,
    pub verdict:         Verdict,
    pub confidence_bps:  u16,
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,
    pub signer_bitmask:  u8,
    /// Final 64-byte aggregated Ed25519 signature (FROST output)
    pub agg_signature:   [u8; 64],
}

/// Collects votes from N daemons, aggregates when M threshold reached
pub struct VoteCollector {
    pub pool:          Pubkey,
    pub nonce:         u64,
    pub threshold:     usize,
    pub known_signers: Vec<Pubkey>,
    votes:             HashMap<Pubkey, DaemonVote>,
}

impl VoteCollector {
    pub fn new(
        pool:          Pubkey,
        nonce:         u64,
        threshold:     usize,
        known_signers: Vec<Pubkey>,
    ) -> Self {
        Self { pool, nonce, threshold, known_signers, votes: HashMap::new() }
    }

    /// Accept a vote. Returns aggregated attestation if threshold reached.
    /// Signature verification happens off-chain before calling this.
    pub fn add_vote(&mut self, vote: DaemonVote) -> Option<AggregatedAttestation> {
        // No double voting
        if self.votes.contains_key(&vote.daemon_id) {
            eprintln!("[collector] duplicate vote from {}", vote.daemon_id);
            return None;
        }

        println!(
            "[collector] vote from {} → {:?} ({}/{} threshold)",
            vote.daemon_id,
            vote.verdict,
            self.votes.len() + 1,
            self.threshold
        );

        self.votes.insert(vote.daemon_id, vote);

        if self.votes.len() >= self.threshold {
            self.aggregate()
        } else {
            None
        }
    }

    fn aggregate(&self) -> Option<AggregatedAttestation> {
        let votes: Vec<&DaemonVote> = self.votes.values().collect();

        // Majority verdict
        let attack_count = votes.iter().filter(|v| v.verdict == Verdict::Attack).count();
        let verdict = if attack_count * 2 >= votes.len() {
            Verdict::Attack
        } else {
            Verdict::Safe
        };

        // Average metrics
        let n = votes.len() as u64;
        let confidence_bps  = (votes.iter().map(|v| v.confidence_bps  as u64).sum::<u64>() / n) as u16;
        let lyapunov_x100   = (votes.iter().map(|v| v.lyapunov_x100   as u64).sum::<u64>() / n) as u32;
        let kolmogorov_x100 = (votes.iter().map(|v| v.kolmogorov_x100 as u64).sum::<u64>() / n) as u32;
        let ricci_x100      = (votes.iter().map(|v| v.ricci_x100      as u64).sum::<u64>() / n) as u32;

        // Build bitmask from known_signers order
        let mut bitmask = 0u8;
        for (i, known) in self.known_signers.iter().enumerate() {
            if self.votes.contains_key(known) {
                bitmask |= 1 << i;
            }
        }

        // The aggregated signature comes from the FROST protocol run
        // in the daemon nodes. Here we use the last received signature
        // as a placeholder — in production the coordinator orchestrates
        // FROST rounds and receives the final aggregated sig.
        let agg_signature = votes.last()?.signature;

        println!(
            "[collector] ✅ aggregated {}/{} | verdict:{:?} | bitmask:{:08b}",
            votes.len(), self.known_signers.len(), verdict, bitmask
        );

        Some(AggregatedAttestation {
            pool: self.pool,
            nonce: self.nonce,
            verdict,
            confidence_bps,
            lyapunov_x100,
            kolmogorov_x100,
            ricci_x100,
            signer_bitmask: bitmask,
            agg_signature,
        })
    }
}
