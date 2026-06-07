mod aggregator;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use solana_sdk::pubkey::Pubkey;
use aggregator::{VoteCollector, DaemonVote, Verdict};

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════╗");
    println!("║   TensorGuard Coordinator  v0.1.0        ║");
    println!("║   FROST Off-chain Aggregator             ║");
    println!("╚══════════════════════════════════════════╝\n");

    let pool      = Pubkey::new_unique();
    let threshold = 2usize;
    let signers   = vec![
        Pubkey::new_unique(), // daemon A
        Pubkey::new_unique(), // daemon B
        Pubkey::new_unique(), // daemon C
    ];

    println!("[coordinator] threshold : {}/{}", threshold, signers.len());
    println!("[coordinator] pool      : {}\n", pool);

    let collector = Arc::new(Mutex::new(
        VoteCollector::new(pool, 1, threshold, signers.clone())
    ));

    println!("[coordinator] listening for daemon votes on :9000...");
    println!("[coordinator] (production: bind TCP, accept FROST partial sigs)\n");

    // Simulate 2 daemon votes with placeholder signatures
    simulate_votes(collector.clone(), &signers).await;
}

async fn simulate_votes(
    collector: Arc<Mutex<VoteCollector>>,
    signers:   &[Pubkey],
) {
    let vote_a = DaemonVote {
        daemon_id:       signers[0],
        verdict:         Verdict::Safe,
        confidence_bps:  7880,
        lyapunov_x100:   10880,
        kolmogorov_x100: 43693,
        ricci_x100:      110,
        signature:       [0u8; 64], // placeholder — real FROST sig in production
    };

    let vote_b = DaemonVote {
        daemon_id:       signers[1],
        verdict:         Verdict::Safe,
        confidence_bps:  7900,
        lyapunov_x100:   10900,
        kolmogorov_x100: 43700,
        ricci_x100:      112,
        signature:       [0u8; 64],
    };

    println!("[daemon A] → vote: SAFE (78.8%)");
    println!("[daemon B] → vote: SAFE (79.0%)");

    let mut lock = collector.lock().await;

    if let Some(att) = lock.add_vote(vote_a) {
        println!("\n[coordinator] threshold not yet reached after vote A");
        drop(att);
    }

    if let Some(att) = lock.add_vote(vote_b) {
        println!("\n[coordinator] ✅ threshold reached!");
        println!("[coordinator] verdict     : {:?}", att.verdict);
        println!("[coordinator] confidence  : {:.1}%", att.confidence_bps as f64 / 100.0);
        println!("[coordinator] bitmask     : {:08b}", att.signer_bitmask);
        println!("[coordinator] → posting post_aggregated TX on-chain...");
    }
}
