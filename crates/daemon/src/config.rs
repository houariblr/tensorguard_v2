/// Runtime configuration — read from env vars or CLI args
pub struct Config {
    /// Solana RPC endpoint (e.g. https://api.mainnet-beta.solana.com)
    pub rpc_url: String,

    /// Path to the daemon's keypair file (Solana CLI format)
    pub keypair_path: String,

    /// TensorGuard program ID (after `anchor deploy`)
    pub program_id: String,

    /// AMM pool account to monitor
    pub pool_pubkey: String,

    /// GuardConfig authority pubkey (the deployer)
    pub authority_pubkey: String,

    /// How often to poll the pool (milliseconds)
    pub poll_interval_ms: u64,

    /// Sliding window size for tensor metrics
    pub window: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            rpc_url: std::env::var("TGD_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".into()),
            keypair_path: std::env::var("TGD_KEYPAIR")
                .unwrap_or_else(|_| "~/.config/solana/id.json".into()),
            program_id: std::env::var("TGD_PROGRAM_ID")
                .expect("TGD_PROGRAM_ID must be set"),
            pool_pubkey: std::env::var("TGD_POOL")
                .expect("TGD_POOL must be set"),
            authority_pubkey: std::env::var("TGD_AUTHORITY")
                .expect("TGD_AUTHORITY must be set"),
            poll_interval_ms: std::env::var("TGD_POLL_MS")
                .unwrap_or_else(|_| "400".into())
                .parse()
                .unwrap_or(400),
            window: std::env::var("TGD_WINDOW")
                .unwrap_or_else(|_| "20".into())
                .parse()
                .unwrap_or(20),
        }
    }
}
