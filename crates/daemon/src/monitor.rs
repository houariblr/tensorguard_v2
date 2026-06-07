use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use tensorguard_core::PoolSnapshot;

/// Raw reserve data extracted from a Raydium CPMM pool account.
/// Layout (simplified): [discriminator:8][...][reserve_a:8][reserve_b:8][...]
///
/// For a real integration, parse the full account layout from the IDL.
/// This offset targets Raydium CPMM token vault amounts.
const RESERVE_A_OFFSET: usize = 253;
const RESERVE_B_OFFSET: usize = 261;

pub struct PoolMonitor {
    pub rpc: RpcClient,
    pub pool: Pubkey,
    pub last_snapshot: Option<PoolSnapshot>,
    block_counter: u64,
}

impl PoolMonitor {
    pub fn new(rpc_url: &str, pool: Pubkey) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url.to_string()),
            pool,
            last_snapshot: None,
            block_counter: 0,
        }
    }

    /// Fetch current pool state and return (prev, curr) snapshot pair if changed.
    pub fn poll(&mut self) -> Option<(PoolSnapshot, PoolSnapshot)> {
        let account = self.rpc.get_account(&self.pool).ok()?;
        let data = account.data;

        if data.len() < RESERVE_B_OFFSET + 8 {
            eprintln!("[monitor] account data too short: {} bytes", data.len());
            return None;
        }

        let reserve_a = u64::from_le_bytes(
            data[RESERVE_A_OFFSET..RESERVE_A_OFFSET + 8].try_into().ok()?
        ) as u128;

        let reserve_b = u64::from_le_bytes(
            data[RESERVE_B_OFFSET..RESERVE_B_OFFSET + 8].try_into().ok()?
        ) as u128;

        let slot = self.rpc.get_slot().unwrap_or(self.block_counter);
        self.block_counter += 1;

        let curr = PoolSnapshot {
            reserve_x: reserve_a,
            reserve_y: reserve_b,
            block: slot,
            timestamp: slot * 400, // ~400ms per slot on Solana
        };

        let result = self.last_snapshot.as_ref().map(|prev| {
            // Only return if reserves actually changed
            if prev.reserve_x != curr.reserve_x || prev.reserve_y != curr.reserve_y {
                Some((prev.clone(), curr.clone()))
            } else {
                None
            }
        }).flatten();

        self.last_snapshot = Some(curr);
        result
    }
}
