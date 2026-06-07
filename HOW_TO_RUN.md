# TensorGuard — How To Run Everything

## Repository Structure

The project is split into **3 workspaces** to avoid dependency conflicts between
`frost-ed25519` and `solana-sdk` (both pin different versions of `zeroize`).

```
tensorguard/
│
├── Cargo.toml                  ← Workspace 1: Math (core + multisig)
├── crates/
│   ├── core/                   Math engine — no external deps
│   ├── multisig/               FROST-Ed25519 threshold signatures
│   ├── daemon/                 Solana daemon
│   ├── coordinator/            Vote aggregator
│   └── solana/
│       └── Cargo.toml          ← Workspace 2: Solana (daemon + coordinator)
│
└── programs/
    └── tensorguard/
        ├── Cargo.toml          ← Workspace 3: Anchor program
        └── src/
```

---

## Prerequisites

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable

# Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
solana --version   # should be >=1.18

# Anchor CLI
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install 0.29.0
avm use 0.29.0
anchor --version   # should be 0.29.0

# Configure for devnet
solana config set --url devnet
solana-keygen new --outfile ~/.config/solana/id.json
solana airdrop 2
```

---

## Step 1 — Build Math Engine (Workspace 1)

```bash
# From project root
cargo build -p tensorguard-core
cargo build -p tensorguard-multisig

# Run tests
cargo test -p tensorguard-core
cargo test -p tensorguard-multisig
# Expected output:
#   test test_full_frost_protocol_2_of_3 ... ok
#   test test_wrong_message_fails ... ok
```

---

## Step 2 — Build Solana Daemon + Coordinator (Workspace 2)

```bash
# From project root
cd crates/solana
cargo build --bin tgd   # daemon
cargo build --bin tgc   # coordinator
```

---

## Step 3 — Build & Deploy Anchor Program (Workspace 3)

```bash
cd programs/tensorguard

# Build
anchor build

# Get the program ID
anchor keys list
# Output: tensorguard: <PROGRAM_ID>

# Deploy to devnet
anchor deploy

# Save the program ID — you'll need it for all steps below
export TGD_PROGRAM_ID="<PROGRAM_ID_FROM_ABOVE>"
```

---

## Step 4 — Generate FROST Key Shares

Run once before starting daemons. Distributes key shares to each node.

```bash
# Example: generate 2-of-3 shares
cargo run -p tensorguard-multisig --example keygen -- \
  --threshold 2 \
  --num-signers 3 \
  --output ./keys/

# Creates:
#   keys/group_pubkey.hex     ← store on-chain (Step 5)
#   keys/daemon_1.key         ← give to daemon node 1 only
#   keys/daemon_2.key         ← give to daemon node 2 only
#   keys/daemon_3.key         ← give to daemon node 3 only
#   keys/pubkey_package.json  ← give to all (public info)
```

---

## Step 5 — Initialize the Guard On-Chain

```bash
# Replace with your actual values
export AUTHORITY_PUBKEY=$(solana-keygen pubkey ~/.config/solana/id.json)
export GROUP_PUBKEY=$(cat keys/group_pubkey.hex)
export DAEMON_A=$(solana-keygen pubkey keys/daemon_a_solana.json)
export DAEMON_B=$(solana-keygen pubkey keys/daemon_b_solana.json)
export DAEMON_C=$(solana-keygen pubkey keys/daemon_c_solana.json)

# Initialize with 2-of-3 multisig
anchor run initialize -- \
  --program-id $TGD_PROGRAM_ID \
  --signers "$DAEMON_A,$DAEMON_B,$DAEMON_C" \
  --threshold 2 \
  --group-pubkey $GROUP_PUBKEY
```

---

## Step 6 — Run Daemon Nodes (3 separate terminals)

Each daemon runs independently with its own key share.

**Terminal 1 — Daemon A:**
```bash
export TGD_RPC_URL="https://api.devnet.solana.com"
export TGD_KEYPAIR="keys/daemon_a_solana.json"
export TGD_FROST_KEY="keys/daemon_1.key"
export TGD_PUBKEY_PKG="keys/pubkey_package.json"
export TGD_PROGRAM_ID="<PROGRAM_ID>"
export TGD_POOL="<RAYDIUM_OR_ORCA_POOL_PUBKEY>"
export TGD_AUTHORITY="<AUTHORITY_PUBKEY>"
export TGD_COORDINATOR_ADDR="127.0.0.1:9000"
export TGD_POLL_MS="400"

cd crates/solana && cargo run --bin tgd
```

**Terminal 2 — Daemon B:**
```bash
export TGD_KEYPAIR="keys/daemon_b_solana.json"
export TGD_FROST_KEY="keys/daemon_2.key"
# ... same other vars
cd crates/solana && cargo run --bin tgd
```

**Terminal 3 — Daemon C:**
```bash
export TGD_KEYPAIR="keys/daemon_c_solana.json"
export TGD_FROST_KEY="keys/daemon_3.key"
# ... same other vars
cd crates/solana && cargo run --bin tgd
```

---

## Step 7 — Run Coordinator (Terminal 4)

The coordinator collects votes from daemons, runs FROST aggregation,
and posts a single transaction on-chain.

```bash
export TGC_BIND_ADDR="127.0.0.1:9000"
export TGC_PROGRAM_ID="<PROGRAM_ID>"
export TGC_KEYPAIR="keys/coordinator_solana.json"    # must be in trusted signers
export TGC_FROST_PUBKEYS="keys/pubkey_package.json"
export TGC_POOL="<POOL_PUBKEY>"
export TGC_AUTHORITY="<AUTHORITY_PUBKEY>"
export TGC_THRESHOLD="2"
export TGC_RPC_URL="https://api.devnet.solana.com"

cd crates/solana && cargo run --bin tgc
```

---

## Step 8 — Integrate Into AMM Swap

Add `guard_verify` as the **first instruction** in every swap transaction:

```typescript
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import { PublicKey, Transaction } from "@solana/web3.js";

const [guardConfig] = PublicKey.findProgramAddressSync(
  [Buffer.from("guard_config"), authority.toBuffer()],
  programId
);

const [aggAttestation] = PublicKey.findProgramAddressSync(
  [Buffer.from("agg_attestation"), pool.toBuffer(), nonceBuffer],
  programId
);

const [poolGuardState] = PublicKey.findProgramAddressSync(
  [Buffer.from("pool_guard_state"), pool.toBuffer()],
  programId
);

const swapTx = new Transaction()
  .add(
    // 1. Guard check (~2,800 CU)
    await program.methods.guardVerify()
      .accounts({
        pool,
        guardConfig,
        voteAccount: aggAttestation,  // pass aggregated attestation here
        poolGuardState,
        caller: wallet.publicKey,
      })
      .instruction()
  )
  .add(
    // 2. Your actual swap instruction
    yourAmmSwapInstruction
  );

await provider.sendAndConfirm(swapTx);
```

---

## Daemon Logs — What to Expect

```
╔══════════════════════════════════════════╗
║   TensorGuard Daemon v0.2.0              ║
║   Predictive + Multisig mode             ║
╚══════════════════════════════════════════╝

[config] daemon   : 7XkR...
[config] pool     : 9mNp...
[daemon] watching pool...

[confirmed] slot:284910   price:1.0482  L:   0.73  K:   1.10  R:  1.00  → ✓ SAFE
[confirmed] slot:284911   price:1.0490  L:   0.81  K:   1.35  R:  1.00  → ✓ SAFE
[predict]   slot:284912   impact:18.2%  projected_price:1.2847          → ⚠️ PRE-BLOCK ATTACK (78.8%)
[predict]   ✅ ATTACK attestation sent to coordinator before block confirms
[heartbeat] ✓ pool: 9mNp...
```

---

## Coordinator Logs — What to Expect

```
╔══════════════════════════════════════════╗
║   TensorGuard Coordinator  v0.1.0        ║
║   FROST Off-chain Aggregator             ║
╚══════════════════════════════════════════╝

[coordinator] threshold: 2/3
[daemon A] → vote received: ATTACK (confidence: 78.8%)
[daemon B] → vote received: ATTACK (confidence: 79.0%)
[coordinator] 2/2 votes — threshold reached
[coordinator] running FROST aggregation...
[coordinator] ✅ single 64-byte Ed25519 sig produced
[coordinator] posting post_aggregated TX...
[attestation] sent | nonce:1842 | verdict:ATTACK | confidence:78.9%
```

---

## Compute Unit Budget

| Instruction | CU Cost |
|---|---|
| `submit_vote` (legacy) | ~5,000 per vote |
| `post_aggregated` (production) | ~3,200 (1 account write + ed25519 sysvar read) |
| `guard_verify` | ~2,800 |
| `heartbeat` | ~1,500 |
| **Total per swap** | **~6,000 CU** |

Raydium CPMM uses ~130,000 CU.
Total with TensorGuard: **~136,000 CU** — safely under the 200,000 CU limit.

---

## Troubleshooting

**`NotFinalized` error on guard_verify:**
→ Coordinator hasn't posted attestation yet. Daemon may be starting up.
→ Wait 1-2 seconds and retry.

**`StaleAttestation` error:**
→ More than 40 slots passed since attestation was posted.
→ Daemon poll interval may be too slow. Set `TGD_POLL_MS=200`.

**`GuardInactive` error:**
→ Guard was disabled via `set_active(false)`.
→ Re-enable: `anchor run set-active -- --active true`

**Fallback mode triggered:**
→ All daemons have been silent for >200 slots (~80s).
→ AMM continues working but unguarded.
→ Check daemon logs. Restart with correct env vars.

**`zeroize` version conflict when building:**
→ Always build math workspace and solana workspace separately.
→ Math: `cargo build` from project root.
→ Solana: `cd crates/solana && cargo build`.
→ Never add `crates/daemon` or `crates/coordinator` to the root Cargo.toml.
