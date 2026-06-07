# TensorGuard

> Pre-execution AMM attack detection using Liquidity Tensor Field analysis.

Most AMM protocols protect themselves with a scalar invariant (`x · y = k`).
This detects damage **after** it happens.

TensorGuard replaces the scalar with a **5-dimensional tensor field** that tracks
the geometry of liquidity in real time — and detects sandwich attacks, flash loans,
and price manipulation **before** the transaction executes.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Off-chain Daemon (Rust)                                    │
│                                                             │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐ │
│  │PoolMonitor  │   │ MempoolMon.  │   │   TensorGuard   │ │
│  │             │   │              │   │                 │ │
│  │ polls RPC   │   │ Jito gRPC /  │   │ Lyapunov  L(T) │ │
│  │ every 400ms │   │ RPC fallback │   │ Kolmogorov K(T)│ │
│  └──────┬──────┘   └──────┬───────┘   │ Ricci     R(T) │ │
│         │  confirmed state │ pending   └────────┬────────┘ │
│         └──────────────────┘                    │          │
│                         Predictor projects      │          │
│                         swap → evaluates ───────┘          │
│                                    │                        │
│                         submit_vote() × N daemons          │
│                         heartbeat()  every 20 slots        │
└─────────────────────────────────────────────────────────────┘
                              │
                    Solana transactions
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Anchor Program (Solana BPF)                                │
│                                                             │
│  initialize()      — deploy, set M/N multisig signers       │
│  submit_vote()     — daemon posts verdict, auto-finalizes   │
│  heartbeat()       — daemon liveness signal every ~8s       │
│  guard_verify()    — AMM gate: PASS / REVERT / FALLBACK     │
│  add_signer()      — rotate daemon set without redeploy     │
│  remove_signer()   — remove compromised daemon              │
│  set_threshold()   — update M in M/N                       │
│  set_active()      — emergency toggle                       │
└─────────────────────────────────────────────────────────────┘
```

---

## The 3 Metrics

| Metric | Formula | Attack signal |
|---|---|---|
| **Lyapunov** `L` | `velocity / baseline_velocity` | `> 5×` normal speed |
| **Kolmogorov** `K` | z-score of price return | `> 3σ` outlier |
| **Ricci** `R` | `observed_curvature / expected_curvature` | `> 3×` geometric tear |

Detection requires **2 of 3** metrics to fire — eliminates false positives.

---

## Security Properties

| Threat | Mechanism |
|---|---|
| **Single daemon compromised** | Multisig M/N — attacker needs M keys |
| **Daemon key is a honeypot** | Rotate via `remove_signer` + `add_signer` without redeploy |
| **Attack before daemon reacts** | Predictive: evaluates mempool swaps on projected state |
| **DoS via daemon shutdown** | 3-path fallback — AMM runs unguarded after 200 slots silence |
| **Replay attack** | Nonce strictly increasing per pool |
| **Stale attestation** | VoteAccount expires after 40 slots (~16s) |
| **Wrong pool spoofing** | VoteAccount PDA seeded by pool pubkey |

---

## Guard Verify — 3 Paths

```
guard_verify()
    │
    ├─ VoteAccount fresh + finalized + Safe   → ✅ PASS
    │
    ├─ VoteAccount fresh + finalized + Attack → ❌ REVERT AttackDetected
    │
    ├─ No VoteAccount + daemon alive          → ❌ REVERT NotFinalized
    │   (daemon will catch up in ms)
    │
    └─ No VoteAccount + daemon silent > 200s  → ⚠️  PASS + FallbackEvent
       (AMM stays live, operators alerted)
```

---

## Simulation Results

```
[ Normal trading — 30 swaps ]
  Block   0 | price: 1.0020 | L:   0.00 | K:   0.00 | R:   0.00 | ✓  ok
  Block  15 | price: 1.0490 | L:   0.84 | K:   1.20 | R:   1.00 | ✓  ok
  Block  29 | price: 1.0962 | L:   0.73 | K:   1.10 | R:   1.00 | ✓  ok

[ Sandwich Attack — front-run 20% of reserves ]
  Block  32 | price: 1.5550 | L: 108.80 | K: 436.93 | R:   1.10 | ⚠️  ATTACK
  Triggers: ["lyapunov", "kolmogorov"]
  Confidence: 78.8%
```

Zero false positives across 30 normal swaps.
Attack detected with 78.8% confidence — before the block confirms.

---

## Project Structure

```
tensorguard/
├── Cargo.toml                              Workspace root
│
├── crates/
│   ├── core/                               Pure Rust math engine
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── tensor/
│   │       │   ├── state.rs                LiquidityTensor (x, y, t, v, ρ)
│   │       │   ├── lyapunov.rs             V(T) — velocity energy
│   │       │   ├── kolmogorov.rs           K(T) — return z-score
│   │       │   └── ricci.rs                R(T) — curvature deviation
│   │       └── detector/
│   │           └── threshold.rs            Triple-gate (2/3 majority)
│   │
│   └── daemon/                             Solana integration daemon
│       └── src/
│           ├── main.rs                     Orchestrator — 2-phase loop
│           ├── config.rs                   Env-based config
│           ├── monitor.rs                  Confirmed pool state poller
│           ├── mempool.rs                  Pending tx monitor (Jito/RPC)
│           ├── predictor.rs                Project swap → tensor state
│           ├── attestation.rs              Build + send submit_vote tx
│           └── heartbeat.rs               Send liveness signal on-chain
│
└── programs/
    └── tensorguard/                        Anchor program (Solana BPF)
        └── src/
            ├── lib.rs                      Program entry points
            ├── state.rs                    GuardConfig, VoteAccount,
            │                               PoolGuardState
            ├── errors.rs                   Custom error codes
            └── instructions/
                ├── initialize.rs           Deploy: M/N signers + threshold
                ├── submit_vote.rs          Daemon vote → auto-finalize
                ├── guard_verify.rs         AMM gate (3-path logic)
                ├── heartbeat.rs            Daemon liveness
                └── manage_signers.rs       add/remove/set_threshold
```

---

## Getting Started

### Prerequisites
- Rust 1.75+
- Anchor CLI 0.29+
- Solana CLI 1.18+

### Build

```bash
# Math engine only (no Solana deps)
cargo build -p tensorguard-core

# Full daemon
cargo build --bin tgd

# Anchor program
anchor build
```

### Deploy to Devnet

```bash
solana config set --url devnet
anchor deploy
### Deploy to Devnet

Deployed on Solana Devnet:
- **Program ID:** `7F6BwxRXzk887AFivMJbnsMcKqyaHBaB5bsbJvttkUq5`
- **Explorer:** [View on Solana Explorer](https://explorer.solana.com/address/7F6BwxRXzk887AFivMJbnsMcKqyaHBaB5bsbJvttkUq5?cluster=devnet)

```

### Initialize (2/3 multisig)

```typescript
await program.methods
  .initialize(
    [daemonA.publicKey, daemonB.publicKey, daemonC.publicKey],
    2  // threshold: 2 of 3
  )
  .accounts({ guardConfig, authority })
  .rpc();
```

### Run Daemon Nodes

```bash
# Run 3 independent instances with different keypairs
TGD_KEYPAIR=~/.config/solana/daemon_a.json \
TGD_PROGRAM_ID=<PROGRAM_ID>               \
TGD_POOL=<POOL_PUBKEY>                    \
TGD_AUTHORITY=<AUTHORITY_PUBKEY>          \
cargo run --bin tgd
```

### Integrate into Your AMM

```typescript
// Add as FIRST instruction in every swap transaction
const swapTx = new Transaction()
  .add(
    await program.methods.guardVerify()
      .accounts({ pool, guardConfig, voteAccount, poolGuardState, caller })
      .instruction()
  )
  .add(/* your swap instruction */);
```

---


## Remaining

See [REMAINING.md](./REMAINING.md).

---

## License

MIT
