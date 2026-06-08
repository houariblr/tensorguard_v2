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
polls RPC          Jito gRPC /          Lyapunov  L(T)
every 400ms   +    RPC fallback    →    Kolmogorov K(T)
                   pending swaps        Ricci      R(T)
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
guard_verify()   — AMM gate: PASS / REVERT / FALLBACK
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
| Attack before daemon reacts | Predictive: projects pending swap state, evaluates tensor |
| DoS via daemon shutdown | 3-path fallback — AMM runs unguarded after 200 slots silence |
| Replay attack | Nonce strictly increasing per pool |
| Stale attestation | Expires after 40 slots (~16 seconds) |
| Wrong pool spoofing | Attestation PDA seeded by pool pubkey |
| Signature spoofing | Ed25519 instruction introspection verifies group_pubkey + pool |

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

## Live Demo — Solana Devnet

| Account | Address |
|---|---|
| Program | `5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG` |
| GuardConfig | `DLbMF6KkC5AE42yaNgKXpWB1yKnvGSRQnWVfk7N9Jcpf` |

[View on Solana Explorer](https://explorer.solana.com/address/5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG?cluster=devnet)

**Verified transactions:**

| Test | TX |
|---|---|
| Safe swap → PASS | `3bQoia8H5D4uhSxJSSTeuQjWGStZB25n9vkJUrfu5tMc` |
| Attack → REVERT | `2fQMzGBzj2XGxm8iNcqwudevK6CaE8YQvZqcm6XfTvvt` |

---

## Project Structure

```
tensorguard_v2/
│
├── Cargo.toml                     Workspace root (core + multisig)
│
├── crates/
│   ├── core/                      Pure Rust math engine (no_std compatible)
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
│   │   └── src/
│   │       ├── keys.rs            Key generation (trusted dealer / DKG)
│   │       ├── protocol.rs        Round 1, Round 2, Aggregation
│   │       └── message.rs         Canonical attestation encoding
│   │
│   ├── daemon/                    Solana integration daemon
│   │   └── src/
│   │       ├── main.rs            2-phase loop (confirmed + predictive)
│   │       ├── config.rs          Env-based configuration
│   │       ├── monitor.rs         Confirmed pool state poller
│   │       ├── mempool.rs         Pending tx monitor (Jito gRPC / RPC fallback)
│   │       ├── predictor.rs       Project swap → tensor state
│   │       ├── attestation.rs     Build + send post_aggregated tx
│   │       └── heartbeat.rs       Daemon liveness signal
│   │
│   └── coordinator/               Off-chain FROST vote aggregator
│       └── src/
│           ├── aggregator.rs      Collect votes, majority verdict, aggregate sig
│           └── main.rs            TCP server + simulation
│
└── programs/
    └── tensorguard/               Anchor program (Solana BPF)
        └── src/
            ├── lib.rs             Program entry points
            ├── state.rs           GuardConfig, AggregatedAttestation, PoolGuardState
            ├── errors.rs          Custom error codes
            └── instructions/
                ├── initialize.rs          Deploy: M/N signers + group_pubkey
                ├── post_aggregated.rs     FROST aggregated attestation
                ├── guard_verify.rs        AMM gate — raw bytes, ~500 CU
                ├── heartbeat.rs           Daemon liveness
                ├── submit_vote.rs         Legacy: individual daemon votes
                └── manage_signers.rs      add / remove / set_threshold
```

---

## Getting Started

### Prerequisites

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

# Node.js (for scripts)
node --version  # >= 18
npm install     # from project root
```

### Build

```bash
# Math engine
cargo build -p tensorguard-core
cargo build -p tensorguard-multisig

# Daemon
cd crates/daemon && cargo build --bin tgd

# Anchor program
cd programs
cargo build-sbf --manifest-path tensorguard/Cargo.toml
solana program deploy tensorguard/target/deploy/tensorguard.so
```

### Initialize

```bash
# Set your program ID in programs/tensorguard/src/lib.rs first, then:
node initialize.js
```

### Run Demo

```bash
npm install tweetnacl
node demo_full.js
```

### Run Tests

```bash
node tests.js
# Expected: 8/8 tests passed
```

---

## Integration

Add `guard_verify` as the **first instruction** in every swap transaction:

```typescript
const swapTx = new Transaction()
  .add(
    // 1. Ed25519 precompile (runtime verifies daemon signature)
    Ed25519Program.createInstructionWithPublicKey({
      publicKey: groupPubkey,
      message:   attestationMessage,
      signature: aggregatedSignature,
    })
  )
  .add(
    // 2. TensorGuard gate (~500 CU)
    await program.methods.guardVerify()
      .accounts({ pool, guardConfig, attestation, poolGuardState,
                  instructionsSysvar, caller })
      .instruction()
  )
  .add(
    // 3. Your swap instruction
    yourAmmSwapInstruction
  );
```

---

## Configuration

See [CONSTANTS.md](./CONSTANTS.md) for all constants that must be set before deployment.

Key values to configure:
- `declare_id!()` — update after `solana program deploy`
- `RESERVE_A_OFFSET` / `RESERVE_B_OFFSET` — match your target AMM layout
- Detection thresholds — calibrate per pool volatility profile

---

## License

MIT
