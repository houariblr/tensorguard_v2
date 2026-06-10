use solana_sdk::signature::Signer;
mod config;
mod monitor;
mod attestation;
mod mempool;
mod predictor;

use std::str::FromStr;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::read_keypair_file;

use tensorguard_core::{LiquidityTensor, TensorGuard};

use config::Config;
use monitor::PoolMonitor;
use attestation::AttestationSender;
use mempool::{MempoolMonitor, MempoolSource};
use predictor::{project_swap, price_impact};

/// Minimum price impact to trigger predictive evaluation (1%)
const PREDICTIVE_IMPACT_THRESHOLD: f64 = 0.01;

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════╗");
    println!("║   TensorGuard Daemon v0.2.0              ║");
    println!("║   Predictive + Multisig mode             ║");
    println!("╚══════════════════════════════════════════╝\n");

    let cfg        = Config::from_env();
    let keypair_path = shellexpand::tilde(&cfg.keypair_path).into_owned();
    let daemon_kp  = read_keypair_file(&keypair_path)
        .unwrap_or_else(|e| panic!("Cannot read keypair: {}", e));

    let program_id = Pubkey::from_str(&cfg.program_id).expect("invalid program_id");
    let pool       = Pubkey::from_str(&cfg.pool_pubkey).expect("invalid pool");
    let authority  = Pubkey::from_str(&cfg.authority_pubkey).expect("invalid authority");

    println!("[config] daemon   : {}", daemon_kp.pubkey());
    println!("[config] pool     : {}", pool);
    println!("[config] rpc      : {}", cfg.rpc_url);

    // ── Init components ───────────────────────────────────────────────────────
    let mut guard   = TensorGuard::with_defaults(cfg.window);
    let mut monitor = PoolMonitor::new(&cfg.rpc_url, pool);
    let mut sender  = AttestationSender::new(program_id, authority, daemon_kp);

    let mempool = MempoolMonitor::new(
        pool,
        MempoolSource::RpcFallback, // swap for Jito { endpoint } in production
        1_000,
    );

    println!("[daemon] watching pool {}...\n", pool);

    // ── Main loop ─────────────────────────────────────────────────────────────
    loop {
        // ── 1. Confirmed state update ─────────────────────────────────────────
        if let Some((prev, curr)) = monitor.poll() {
            let tensor = LiquidityTensor::from_snapshots(&prev, &curr);
            let signal = guard.evaluate(&tensor);

            println!(
                "[confirmed] slot:{:<8} price:{:.4} L:{:>7.2} K:{:>7.2} R:{:>5.2} → {}",
                curr.block,
                tensor.price(),
                signal.lyapunov,
                signal.kolmogorov,
                signal.ricci,
                if signal.is_attack {
                    format!("⚠️  ATTACK ({:.1}%)", signal.confidence * 100.0)
                } else {
                    "✓  SAFE".into()
                }
            );

            // Post attestation based on confirmed state
            if let Err(e) = sender.send(&monitor.rpc, &pool, &signal) {
                eprintln!("[attestation] send failed: {}", e);
            }
        }

        // ── 2. Predictive evaluation — pending swaps ──────────────────────────
        if let Some(current_snapshot) = &monitor.last_snapshot {
            let pending = mempool.subscribe(&monitor.rpc);

            for swap in &pending {
                let impact = price_impact(current_snapshot, swap);

                // Only analyze swaps large enough to matter
                if impact < PREDICTIVE_IMPACT_THRESHOLD {
                    continue;
                }

                // Project pool state AFTER this swap executes
                let projected = project_swap(current_snapshot, swap);
                let projected_tensor = LiquidityTensor::from_snapshots(
                    current_snapshot,
                    &projected,
                );

                // Run TensorGuard on projected state — without updating history
                // (we use a separate guard instance to avoid polluting the confirmed state)
                let mut predictive_guard = TensorGuard::with_defaults(cfg.window);
                let signal = predictive_guard.evaluate(&projected_tensor);

                println!(
                    "[predict]  slot:{:<8} impact:{:.1}% projected_price:{:.4} → {}",
                    swap.slot,
                    impact * 100.0,
                    projected_tensor.price(),
                    if signal.is_attack {
                        format!("⚠️  PRE-BLOCK ATTACK DETECTED ({:.1}%)", signal.confidence * 100.0)
                    } else {
                        "✓  ok".into()
                    }
                );

                // If projected state looks like an attack → post ATTACK attestation NOW
                // before the swap lands on-chain
                if signal.is_attack {
                    if let Err(e) = sender.send(&monitor.rpc, &pool, &signal) {
                        eprintln!("[predictive attestation] send failed: {}", e);
                    } else {
                        println!("[predict]  ✅ ATTACK attestation posted before block confirms");
                    }
                }
            }
        }

        // ── 3. Adaptive sleep — reduce CPU when pool is idle ──────────────────
        // idle_count=0  → data changed     → poll fast  (400ms)
        // idle_count=1  → 1 idle poll      → slow down  (800ms)
        // idle_count=5+ → 5+ idle polls    → max backoff (2000ms)
        let sleep_ms = match monitor.idle_count {
            0      => cfg.poll_interval_ms,
            1..=4  => cfg.poll_interval_ms * 2,
            _      => cfg.poll_interval_ms * 5,
        };

        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }
}
