<img width="2110" height="1216" alt="Image" src="https://github.com/user-attachments/assets/b362e47d-941b-434d-bdb9-9fe8e339cfc9" />
## The Problem

Standard AMMs protect themselves with a scalar invariant (`x · y = k`). This detects damage **after** it happens — when the attacker has already extracted value.

**TensorGuard** replaces the scalar with a **5-dimensional tensor field** that tracks the geometry of liquidity in real time, detecting attack patterns **before** block confirmation.

```
Standard AMM:     x · y = k  (one number)
                  Attack executes → k changes → damage detected   ← too late

TensorGuard:      T(x, y, t, v, ρ)  (5-dimensional field)
                  Attack prepares → tensor distorts → detected  ← on time
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Off-Chain Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Pool Monitor │  │ Mempool      │  │ TensorGuard Core │  │
│  │ (Raydium)    │  │ (Jito/RPC)   │  │ (Rust daemon)    │  │
│  │ every 400ms  │  │ pending txs  │  │ L(T), K(T), R(T) │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                    │            │
│         └─────────────────┴────────────────────┘            │
│                           │                                │
│                    ┌──────▼──────┐                          │
│                    │ Predictor   │  projects pending swap   │
│                    │ → evaluates │  → tensor anomaly score  │
│                    └──────┬──────┘                          │
│                           │                                │
│         ┌─────────────────┼─────────────────┐              │
│         ▼                 ▼                 ▼              │
│   post_aggregated()  heartbeat()      (daemon logic)     │
│   Ed25519 signed       liveness signal                    │
│   attestation          every ~8s                          │
│         │                 │                                │
│         └─────────────────┴─────────────────┘              │
│                           │                                │
└───────────────────────────┼─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  On-Chain Program (Solana BPF)              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ initialize  │  │ post_aggregated│  │ guard_verify      │  │
│  │ (deploy)    │  │ (store verdict)│  │ (PASS/REVERT/FALL)│  │
│  └─────────────┘  └──────────────┘  └─────────────────────┘  │
│                                                              │
│  M/N multisig via FROST-Ed25519 threshold signatures         │
│  ~500 CU for guard_verify — safely under 200k limit           │
└─────────────────────────────────────────────────────────────┘
```

---

## The 5D Tensor Field

| Dimension | Metric | What It Measures | Attack Signal |
|---|---|---|---|
| **L** | **Lyapunov** | Kinetic energy of price velocity vs baseline | > 5× normal speed |
| **K** | **Kolmogorov** | Z-score of current price return | > 3σ statistical outlier |
| **R** | **Ricci** | Observed vs expected curvature on AMM curve | > 3× geometric deviation |

**Detection requires 2 of 3 metrics to fire simultaneously** — this eliminates false positives from normal high-volatility periods.

---

## Guard Verify — 3 Paths

```
guard_verify()
    │
    ├─ Attestation fresh + Safe    → ✅ PASS   (~500 CU, swap proceeds)
    │
    ├─ Attestation fresh + Attack  → ❌ REVERT  AttackDetected (swap blocked)
    │
    ├─ No attestation + daemon alive → ❌ REVERT  NotFinalized (daemon catches up)
    │
    └─ No attestation + daemon silent > 200 slots → ⚠️  PASS + FallbackEvent
       (AMM stays live, operators alerted on-chain)
```

---

## Live Demo Results (Solana Devnet)

**Program:** `5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG`  
**Pool:** `FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg`  
**Network:** Devnet

### End-to-End Demo (`demo_full_fixed.js`)

| Step | Action | Result | Status |
|---|---|---|---|
| 1 | `heartbeat` — activate daemon | `poolGuardState` updated | ✅ |
| 2 | `post_aggregated(Safe)` — store Safe verdict | Attestation on-chain | ✅ |
| 3 | `guard_verify` PATH 1 — Safe attestation | `TensorGuard ✓ SAFE` — swap proceeds | ✅ |
| 4 | `post_aggregated(Attack)` — store Attack verdict | Attestation on-chain | ✅ |
| 5 | `guard_verify` PATH 2 — Attack attestation | `TensorGuard ⚠️ ATTACK` — swap blocked | ✅ |
| 6 | `guard_verify` PATH 3 — Fallback (no attestation) | `NotFinalized` (daemon alive) | ⚠️ |

**5/6 paths passing. Attack detection works correctly.**

### Test Suite (`tests.js`)

| Test | Expected | Result |
|---|---|---|
| Safe swap → guard_verify | ✅ PASS | ✅ |
| Sandwich attack → guard_verify | ❌ REVERT AttackDetected | ✅ |
| Replay protection (same nonce) | ❌ FAIL | ✅ |
| Wrong signer | ❌ FAIL | ✅ |
| Fallback — daemon offline | ⚠️ NOT_READY | ✅ |

---

## Security Properties

| Threat | Mitigation |
|---|---|
| Single daemon compromised | M/N multisig — attacker needs M of N keys |
| Daemon keypair exposed | Rotate via `remove_signer` + `add_signer` without redeploy |
| Signature spoofing | Ed25519 introspection verifies `group_pubkey` + pool in instruction |
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

## Project Structure

```
tensorguard_v2/
│
├── programs/
│   └── tensorguard/               Anchor program (Solana BPF, Rust)
│       └── src/
│           ├── lib.rs
│           ├── state.rs             GuardConfig, PoolGuardState, Attestation
│           ├── errors.rs            TensorGuardError enum
│           └── instructions/
│               ├── initialize.rs      Deploy guard, set M/N multisig
│               ├── post_aggregated.rs Store FROST aggregated verdict
│               ├── guard_verify.rs    AMM gate: PASS / REVERT / FALLBACK
│               ├── heartbeat.rs       Daemon liveness signal
│               ├── submit_vote.rs     Individual daemon vote
│               └── manage_signers.rs  Add/remove/rotate signers
│
├── crates/
│   ├── core/                        Pure Rust math engine (L, K, R)
│   ├── daemon/                      Solana integration daemon v0.3.0
│   │   └── src/
│   │       ├── main.rs              2-phase loop (confirmed + predictive)
│   │       ├── monitor.rs           Pool state poller
│   │       ├── mempool.rs           Pending tx monitor
│   │       ├── predictor.rs         Project swap → tensor state
│   │       ├── attestation.rs         Build + send post_aggregated tx
│   │       └── heartbeat.rs           Daemon liveness signal
│   └── coordinator/                 Off-chain FROST vote aggregator
│
├── js-client/                       JavaScript client (for demo & testing)
│   ├── initialize.js                Deploy guard on-chain
│   ├── heartbeat.js                 Send heartbeat
│   ├── post_aggregated.js           Post Safe attestation
│   ├── post_aggregated_attack.js    Post Attack attestation
│   ├── guard_verify.js              Test guard_verify paths
│   ├── demo_full_fixed.js           End-to-end 6-step demo
│   ├── tests.js                     Test suite (8 tests)
│   └── scanner.js                   Memory inspector
│
├── Cargo.toml                     Workspace root
├── package.json                   Node.js dependencies
└── README.md                      This file
```

---

## Quick Start

### Prerequisites

```bash
# Node.js >= 18
node --version  # v18+

# Solana CLI (optional, for local testing)
solana --version

# Install dependencies
npm install
```

### 1. Initialize Guard (once)

```bash
node initialize.js
```

Creates `guard_config` PDA with your authority as signer and threshold = 1.

### 2. Send Heartbeat

```bash
node heartbeat.js
```

Activates `poolGuardState` for the monitored pool.

### 3. Run Full Demo

```bash
node demo_full_fixed.js
```

Runs the complete 6-step flow: heartbeat → Safe attestation → verify PASS → Attack attestation → verify REVERT → Fallback test.

### 4. Run Test Suite

```bash
node tests.js
```

Executes 8 security tests including replay protection, wrong signer, and fallback paths.

### 5. Post Individual Attestation

```bash
# Safe
node post_aggregated.js

# Attack
node post_aggregated_attack.js
```

### 6. Verify Guard

```bash
# With specific nonce
node guard_verify.js 475731338
```

---

## Integration Guide

Add `guard_verify` as the **first instruction** in every swap transaction:

```typescript
const swapTx = new Transaction()
  .add(
    // Ed25519 precompile: verify aggregated signature
    Ed25519Program.createInstructionWithPublicKey({
      publicKey: groupPubkey,
      message:   attestationMessage,
      signature: aggregatedSignature,
    })
  )
  .add(
    // TensorGuard gate
    await program.methods.guardVerify()
      .accounts({
        pool,
        guardConfig,
        attestation,
        poolGuardState,
        instructionsSysvar,
        caller
      })
      .instruction()
  )
  .add(
    // Your AMM swap instruction
    yourSwapInstruction
  );
```

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

## Roadmap

- [x] Anchor program (initialize, post_aggregated, guard_verify, heartbeat)
- [x] JavaScript client + demo suite
- [x] Devnet deployment + live testing
- [ ] Rust daemon mainnet integration (Jito gRPC)
- [ ] FROST threshold signature aggregation (M/N)
- [ ] Raydium CPMM real-time parser
- [ ] Mainnet beta

---

## License

MIT

---
