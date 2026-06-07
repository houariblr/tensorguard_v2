use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

use crate::predictor::{PendingSwap, SwapDirection};

/// Mempool source — either Jito gRPC (production) or RPC polling (fallback)
pub enum MempoolSource {
    /// Jito Block Engine gRPC stream.
    /// Provides ~100ms latency on pending transactions.
    /// Endpoint: https://mainnet.block-engine.jito.wtf
    Jito { endpoint: String },

    /// Fallback: poll RPC for transactions touching the pool.
    /// Higher latency (~400ms) but no external dependency.
    RpcFallback,
}

/// Monitors the Solana mempool for large swaps targeting a specific pool.
pub struct MempoolMonitor {
    pub pool:   Pubkey,
    pub source: MempoolSource,

    /// Minimum swap size to analyze (ignore dust transactions)
    pub min_swap_amount: u128,
}

impl MempoolMonitor {
    pub fn new(pool: Pubkey, source: MempoolSource, min_swap_amount: u128) -> Self {
        Self { pool, source, min_swap_amount }
    }

    /// Subscribe to pending swaps.
    /// Returns an iterator of PendingSwap events.
    ///
    /// Production: replace this with a tokio::sync::mpsc channel
    /// fed by the Jito gRPC stream.
    pub fn subscribe(&self, rpc: &RpcClient) -> Vec<PendingSwap> {
        match &self.source {
            MempoolSource::Jito { endpoint } => {
                // TODO: connect to Jito gRPC
                // use tonic to subscribe to:
                //   jito_protos::searcher::MempoolSubscription { programs: [pool] }
                // Each event gives us the raw transaction bytes.
                // Parse the swap instruction to extract amount_in + direction.
                eprintln!("[mempool] Jito endpoint: {} — gRPC not yet wired", endpoint);
                vec![]
            }

            MempoolSource::RpcFallback => {
                self.poll_rpc_signatures(rpc)
            }
        }
    }

    /// RPC fallback: fetch recent confirmed signatures and infer pending swaps.
    /// This is approximate — confirmed ≠ pending, but acceptable for devnet testing.
    fn poll_rpc_signatures(&self, rpc: &RpcClient) -> Vec<PendingSwap> {
        let sigs = match rpc.get_signatures_for_address(&self.pool) {
            Ok(s)  => s,
            Err(e) => {
                eprintln!("[mempool] rpc error: {}", e);
                return vec![];
            }
        };

        // Take only the most recent unconfirmed-looking signatures
        let slot = rpc.get_slot().unwrap_or(0);

        sigs.into_iter()
            .filter(|s| s.err.is_none())
            .take(3)
            .filter_map(|sig_info| {
                // Parse transaction to extract swap amount.
                // For now we emit a synthetic PendingSwap based on slot recency.
                // Real implementation: rpc.get_transaction() + decode instruction data.
                let tx_slot = sig_info.slot;
                if slot.saturating_sub(tx_slot) > 2 {
                    return None; // too old
                }

                // Synthetic: we cannot know amount without decoding, so we return
                // a sentinel that triggers projection with a conservative estimate.
                // Replace with real decoding in production.
                Some(PendingSwap {
                    amount_in: self.min_swap_amount,
                    direction: SwapDirection::ZeroForOne,
                    slot: tx_slot,
                })
            })
            .collect()
    }
}

/// Parse a raw Raydium CPMM swap instruction to extract amount_in + direction.
/// Instruction layout (simplified):
///   [discriminator:8][amount_in:8][min_amount_out:8][zero_for_one:1]
pub fn parse_swap_instruction(data: &[u8]) -> Option<(u128, SwapDirection)> {
    if data.len() < 17 {
        return None;
    }
    // Skip 8-byte Anchor discriminator
    let amount_in = u64::from_le_bytes(data[8..16].try_into().ok()?) as u128;
    let zero_for_one = data[16] != 0;

    let direction = if zero_for_one {
        SwapDirection::ZeroForOne
    } else {
        SwapDirection::OneForZero
    };

    Some((amount_in, direction))
}
