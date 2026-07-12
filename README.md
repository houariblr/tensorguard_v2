# TensorGuard

> Pre-execution AMM attack detection using Liquidity Tensor Field analysis on Solana.

Most AMM protocols protect themselves with a scalar invariant (`x · y = k`).
This detects damage **after** it happens.

TensorGuard replaces the scalar with a **5-dimensional tensor field** that tracks
the geometry of liquidity in real time — detecting sandwich attacks, flash loans,
and price manipulation **before** the transaction executes.

---

## The Problem

```
Standard AMM invariant: x · y = k  (one number)

Attack executes → k changes → damage detected   ← too late

TensorGuard:    T(x, y, t, v, ρ)  (5-dimensional field)

Attack prepares → tensor distorts → detected before execution  ← on time
```

---

## How It Works

```
Off-chain Daemon (Rust)
─────────────────────────────────────────────────────────
PoolMonitor        MempoolMonitor       TensorGuard Core
Raydium CPMM  +    Jito gRPC /          Lyapunov  L(T)
real parser        RPC fallback    →    Kolmogorov K(T)
every 400ms        pending swaps        Ricci      R(T)
                        │
                   Predictor: projects swap → evaluates tensor
                        │
                post_aggregated() → single Ed25519 signed attestation
                heartbeat()       → daemon liveness every ~8s
                        │
                Solana transactions
                        ▼
Anchor Program (Solana BPF)
─────────────────────────────────────────────────────────
initialize()     — deploy, set M/N multisig signers
post_aggregated()— coordinator posts FROST aggregated verdict
heartbeat()      — daemon liveness signal
guard_verify()   — AMM gate: PASS / REVERT / FALLBACK (~500 CU)
add_signer()     — rotate daemon set without redeploy
remove_signer()  — remove compromised daemon
set_threshold()  — update M in M/N
set_active()     — emergency toggle
```

---

## The 3 Metrics

| Metric | What It Measures | Attack Signal |
|---|---|---|
| **Lyapunov** `L(T)` | Kinetic energy of price velocity vs baseline | > 5× normal speed |
| **Kolmogorov** `K(T)` | Z-score of current price return | > 3σ statistical outlier |
| **Ricci** `R(T)` | Observed vs expected curvature on AMM curve | > 3× geometric deviation |

Detection requires **2 of 3** metrics to fire simultaneously — eliminates false positives
from normal high-volatility periods.

---

## Guard Verify — 3 Paths

```
guard_verify()
    │
    ├─ Attestation fresh + Safe    → ✅ PASS   (~500 CU)
    │
    ├─ Attestation fresh + Attack  → ❌ REVERT AttackDetected
    │
    ├─ No attestation + daemon alive → ❌ REVERT NotFinalized
    │   (daemon catches up in milliseconds)
    │
    └─ No attestation + daemon silent > 200 slots → ⚠️  PASS + FallbackEvent
       (AMM stays live, operators alerted on-chain)
```

---

## Security Properties

| Threat | Mechanism |
|---|---|
| Single daemon compromised | Multisig M/N — attacker needs M keys |
| Daemon keypair exposed | Rotate via `remove_signer` + `add_signer` without redeploy |
| Signature spoofing | Ed25519 introspection verifies group_pubkey + pool in instruction |
| Attack before daemon reacts | Predictive: projects pending swap state, evaluates tensor |
| DoS via daemon shutdown | 3-path fallback — AMM runs unguarded after 200 slots silence |
| Replay attack | Nonce strictly increasing per pool |
| Stale attestation | Expires after 40 slots (~16 seconds) |
| Wrong pool spoofing | Attestation PDA seeded by pool pubkey |

---

## Compute Budget

| Instruction | CU Cost |
|---|---|
| `post_aggregated` | ~3,200 |
| `guard_verify` | ~500 |
| `heartbeat` | ~1,500 |
| **Total overhead per swap** | **~5,200 CU** |

Raydium CPMM uses ~130,000 CU. Total with TensorGuard: **~135,200 CU** — safely under the 200,000 CU limit.

---

## Simulation Results

```
[ Normal trading — 30 swaps ]
  Block   0 | price: 1.0020 | L:   0.00 | K:   0.00 | R: 1.00 | ✓  ok
  Block  15 | price: 1.0490 | L:   0.84 | K:   1.20 | R: 1.00 | ✓  ok
  Block  29 | price: 1.0962 | L:   0.73 | K:   1.10 | R: 1.00 | ✓  ok

[ Sandwich Attack — front-run 20% of reserves ]
  Block  32 | price: 1.5550 | L: 108.80 | K: 436.93 | R: 1.10 | ⚠️  ATTACK
  Triggers: ["lyapunov", "kolmogorov"]
  Confidence: 78.8%

Zero false positives across 30 normal swaps.
Attack detected with 78.8% confidence before the block confirms.
```

---

## Real Pool Monitoring — Mainnet

TensorGuard daemon monitors real Raydium CPMM pools using the verified pool layout:

```
Pool:   7JuwJuNU88gurFnyWeiyGKbFmExMWcmRZntn9imEzdny  (SOL/USDC)
Vault0: 7VLUXrnSSDo9BfCa4NWaQs68g7ddDY1sdXBKW6Xswj9Y
Vault1: 3rzbbW5Q8MA7sCaowf28hNgACNPecdS2zceWy7Ptzua9

[slot 427804275] ✓  SAFE | Price: $67.6571 | R0: 1.9965 | R1: 135.0755
                🟢 Lyapunov: 0 | 🟢 Kolmogorov: 0 | 🟢 Ricci: 0
```

Run the real-time monitor:
```bash
node pool_monitor_real.js
```

---

## Live Demo — Solana Devnet

| Account | Address |
|---|---|
| Program | `J9HjhTSMEgFHfriUVhMNDrZaoGreDVJ1X7b97KmqMmTU` |
| GuardConfig | `3xswi8HHUkCC6LmNJnazebs4HxGHNSnRvRNTVxumiREd` |

[View on Solana Explorer](https://explorer.solana.com/address/J9HjhTSMEgFHfriUVhMNDrZaoGreDVJ1X7b97KmqMmTU?cluster=devnet)

**Verified transactions — 8/8 tests passing:**

| Test | Result |
|---|---|
| Safe swap → guard_verify | ✅ PASS |
| Sandwich attack → guard_verify | ❌ REVERT AttackDetected |
| Replay protection | ❌ FAIL (correct) |
| Wrong signer | ❌ FAIL (correct) |
| Fallback — daemon offline | ⚠️ NOT_READY |

---

## Project Structure

```
tensorguard_v2/
│
├── Cargo.toml                     Workspace root (core + multisig)
│
├── crates/
│   ├── core/                      Pure Rust math engine
│   │   └── src/
│   │       ├── tensor/
│   │       │   ├── state.rs       LiquidityTensor (x, y, t, velocity, density)
│   │       │   ├── lyapunov.rs    V(T) — velocity energy ratio
│   │       │   ├── kolmogorov.rs  K(T) — return z-score
│   │       │   └── ricci.rs       R(T) — curvature deviation
│   │       └── detector/
│   │           └── threshold.rs   Triple-gate 2/3 majority vote
│   │
│   ├── multisig/                  FROST-Ed25519 threshold signatures (RFC 9591)
│   │
│   ├── daemon/                    Solana integration daemon v0.3.0
│   │   └── src/
│   │       ├── main.rs            2-phase loop (confirmed + predictive)
│   │       ├── cpmm_parser.rs     Raydium CPMM real layout parser ← NEW
│   │       ├── monitor.rs         Real pool state poller
│   │       ├── mempool.rs         Pending tx monitor (Jito gRPC / RPC fallback)
│   │       ├── predictor.rs       Project swap → tensor state
│   │       ├── attestation.rs     Build + send post_aggregated tx
│   │       └── heartbeat.rs       Daemon liveness signal
│   │
│   └── coordinator/               Off-chain FROST vote aggregator
│
├── programs/
│   └── tensorguard/               Anchor program (Solana BPF)
│       └── src/
│           ├── lib.rs
│           ├── state.rs
│           ├── errors.rs
│           └── instructions/
│               ├── initialize.rs
│               ├── post_aggregated.rs
│               ├── guard_verify.rs
│               ├── heartbeat.rs
│               ├── submit_vote.rs
│               └── manage_signers.rs
│
├── pool_monitor_real.js           Real-time Raydium CPMM monitor ← NEW
├── demo_full.js                   End-to-end demo (3 paths)
├── tests.js                       Test suite (8/8 passing)
├── initialize.js                  Deploy guard on-chain
└── run_daemon.sh                  Start daemon
```

---

## Getting Started

### Prerequisites

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

# Node.js >= 18
npm install
npm install tweetnacl
```

### Build

```bash
# Math engine
cargo build -p tensorguard-core

# Daemon
cd crates/daemon && cargo build --release --bin tgd

# Anchor program
cd programs
cargo build-sbf --manifest-path tensorguard/Cargo.toml
solana program deploy tensorguard/target/deploy/tensorguard.so
```

### Deploy & Run

```bash
# 1. Initialize guard on-chain
node initialize.js

# 2. Run heartbeat
node heartbeat.js

# 3. Run full demo
node demo_full.js

# 4. Run test suite
node tests.js

# 5. Monitor real Raydium pool
node pool_monitor_real.js

# 6. Start daemon
bash run_daemon.sh
```

### Integration

Add `guard_verify` as the **first instruction** in every swap transaction:

```typescript
const swapTx = new Transaction()
  .add(
    Ed25519Program.createInstructionWithPublicKey({
      publicKey: groupPubkey,
      message:   attestationMessage,
      signature: aggregatedSignature,
    })
  )
  .add(
    await program.methods.guardVerify()
      .accounts({ pool, guardConfig, attestation, poolGuardState,
                  instructionsSysvar, caller })
      .instruction()
  )
  .add(yourAmmSwapInstruction);
```

---

## License

MIT
