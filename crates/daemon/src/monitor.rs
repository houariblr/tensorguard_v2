use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use tensorguard_core::PoolSnapshot;

const RESERVE_A_OFFSET: usize = 253;
const RESERVE_B_OFFSET: usize = 261;

pub struct PoolMonitor {
    pub rpc: RpcClient,
    pub pool: Pubkey,
    pub last_snapshot: Option<PoolSnapshot>,
    block_counter: u64,
    /// Hash of last account data — skip processing if unchanged
    last_data_hash: u64,
    /// Consecutive idle polls — used for adaptive sleep signal
    pub idle_count: u32,
}

impl PoolMonitor {
    pub fn new(rpc_url: &str, pool: Pubkey) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url.to_string()),
            pool,
            last_snapshot: None,
            block_counter: 0,
            last_data_hash: 0,
            idle_count: 0,
        }
    }

    /// Fast hash of reserve bytes — avoid full processing if data unchanged
    fn hash_reserves(data: &[u8]) -> u64 {
        if data.len() < RESERVE_B_OFFSET + 8 {
            return 0;
        }
        let a = u64::from_le_bytes(data[RESERVE_A_OFFSET..RESERVE_A_OFFSET+8].try_into().unwrap_or([0u8;8]));
        let b = u64::from_le_bytes(data[RESERVE_B_OFFSET..RESERVE_B_OFFSET+8].try_into().unwrap_or([0u8;8]));
        // Simple mix hash
        a.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(b)
    }

    /// Fetch current pool state and return (prev, curr) snapshot pair if changed.
    pub fn poll(&mut self) -> Option<(PoolSnapshot, PoolSnapshot)> {
        let account = self.rpc.get_account(&self.pool).ok()?;
        let data = account.data;

        if data.len() < RESERVE_B_OFFSET + 8 {
            eprintln!("[monitor] account data too short: {} bytes", data.len());
            return None;
        }

        // ── Fast path: skip if data unchanged ────────────────────────────────
        let new_hash = Self::hash_reserves(&data);
        if new_hash == self.last_data_hash {
            self.idle_count = self.idle_count.saturating_add(1);
            return None;
        }
        self.last_data_hash = new_hash;
        self.idle_count = 0;

        // ── Data changed — process ────────────────────────────────────────────
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
            timestamp: slot * 400,
        };

        let result = self.last_snapshot.as_ref().map(|prev| {
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
