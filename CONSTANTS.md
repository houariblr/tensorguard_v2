# TensorGuard — Constants Reference

Every constant you must know before running the project.
Grouped by: **Must Change**, **Calibrate Per Pool**, **Stable Defaults**.

---

## 🔴 Must Change Before Running

### 1. Program ID — `programs/tensorguard/src/lib.rs`

```rust
// CURRENT (fake — won't deploy):
declare_id!("TGrd1111111111111111111111111111111111111111");

// After `anchor deploy`, replace with real ID:
declare_id!("<YOUR_PROGRAM_ID_FROM_ANCHOR_DEPLOY>");
```

**How to get it:**
```bash
anchor build
anchor keys list
# Output: tensorguard: AbCd1234...
```

---

### 2. Pool Layout Offsets — `crates/daemon/src/monitor.rs`

```rust
// Current values target Raydium CPMM:
const RESERVE_A_OFFSET: usize = 253;
const RESERVE_B_OFFSET: usize = 261;
```

**How to verify for your target AMM:**
```bash
# Fetch pool account and inspect bytes
solana account <POOL_PUBKEY> --output json | python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
raw = base64.b64decode(data['value']['data'][0])
print(f'Account size: {len(raw)} bytes')
# Print bytes around expected reserve positions
for i in range(240, 280):
    print(f'  offset {i}: {int.from_bytes(raw[i:i+8], \"little\")}')"
```

**Known offsets:**
| AMM | RESERVE_A_OFFSET | RESERVE_B_OFFSET |
|---|---|---|
| Raydium CPMM | 253 | 261 |
| Raydium AMM v4 | 101 | 117 |
| Orca Whirlpool | 189 | 197 |

---

## ✅ Verified — Do Not Change

### 3. Anchor Instruction Discriminators

These are computed from `sha256("global:<instruction_name>")[0..8]`.
**Already correct in the codebase** after our fix.

| Instruction | Discriminator |
|---|---|
| `initialize` | `[175, 175, 109, 31, 13, 152, 155, 237]` |
| `submit_vote` | `[115, 242, 100, 0, 49, 178, 242, 133]` |
| `post_aggregated` | `[89, 99, 3, 196, 67, 157, 165, 80]` |
| `guard_verify` | `[215, 255, 83, 127, 169, 196, 213, 38]` |
| `heartbeat` | `[202, 104, 56, 6, 240, 170, 63, 134]` |
| `add_signer` | `[76, 104, 61, 51, 179, 139, 47, 222]` |
| `remove_signer` | `[212, 32, 97, 47, 61, 67, 184, 141]` |
| `set_threshold` | `[155, 53, 245, 104, 116, 169, 239, 167]` |
| `set_active` | `[29, 16, 225, 132, 38, 216, 206, 33]` |

**To recompute any discriminator:**
```bash
echo -n "global:post_aggregated" | sha256sum | cut -c1-16 | \
  python3 -c "import sys; h=bytes.fromhex(sys.stdin.read().strip()); print(list(h[:8]))"
```

---

## 🟡 Calibrate Per Pool

### 4. Attestation Freshness — `programs/tensorguard/src/state.rs`

```rust
// VoteAccount and AggregatedAttestation
pub const MAX_AGE_SLOTS: u64 = 40;  // ~16 seconds
```

| Network | Slot time | 40 slots = |
|---|---|---|
| Mainnet | ~400ms | ~16 seconds |
| Devnet | ~400ms | ~16 seconds |

**Increase if your daemon poll interval is slow:**
```rust
pub const MAX_AGE_SLOTS: u64 = 80;  // ~32 seconds for slow networks
```

---

### 5. Daemon Silence Fallback — `programs/tensorguard/src/state.rs`

```rust
pub const MAX_DAEMON_SILENCE_SLOTS: u64 = 200;  // ~80 seconds
```

**Tradeoff:**
- Lower (e.g. 50) → faster fallback, less protection window
- Higher (e.g. 500) → longer protection window, slower fallback

---

### 6. TensorGuard Detection Thresholds — `crates/core/src/detector/threshold.rs`

```rust
pub fn default() -> Self {
    Self {
        lyapunov:    5.0,   // 5× faster than historical baseline
        kolmogorov:  3.0,   // 3 standard deviations from mean return
        ricci:       3.0,   // 3× larger than expected curve deviation
    }
}
```

**Calibration guide:**
| Pool type | Lyapunov | Kolmogorov | Ricci | Notes |
|---|---|---|---|---|
| Stable pairs (USDC/USDT) | 3.0 | 2.5 | 2.0 | Low volatility — tighter |
| Major pairs (SOL/USDC) | 5.0 | 3.0 | 3.0 | Default |
| Meme/volatile pairs | 8.0 | 4.0 | 5.0 | High volatility — looser |

**How to calibrate:**
1. Run daemon in monitoring-only mode for 48 hours
2. Collect L, K, R values during normal trading
3. Set thresholds at: `mean + 3×std` of observed values

---

### 7. Predictive Impact Threshold — `crates/daemon/src/main.rs`

```rust
const PREDICTIVE_IMPACT_THRESHOLD: f64 = 0.01;  // 1% price impact
```

**Meaning:** Only analyze pending swaps that would move price by ≥ 1%.
- Set lower (0.005) for stable pools
- Set higher (0.03) for volatile pools to reduce noise

---

## 🟢 Stable Defaults — Usually No Need to Change

### 8. Max Signers — `programs/tensorguard/src/state.rs`

```rust
pub const MAX_SIGNERS: usize = 5;
```

Maximum daemon nodes in the trusted set.
Change only if you need more than 5 nodes. Requires redeployment.

---

### 9. Heartbeat Interval — `crates/daemon/src/main.rs`

```bash
# Controlled via env var (not a hardcoded constant)
TGD_POLL_MS=400   # poll every 400ms
```

Heartbeat is sent every ~20 polls = every ~8 seconds.
`MAX_DAEMON_SILENCE_SLOTS` (200 slots × 400ms = 80s) gives 10× margin.

---

## Quick Checklist Before First Deploy

```
[ ] Replace declare_id!() after anchor deploy
[ ] Verify RESERVE_A_OFFSET and RESERVE_B_OFFSET for your AMM
[ ] Discriminators are already correct — no action needed
[ ] Set MAX_AGE_SLOTS based on your daemon poll speed
[ ] Set detection thresholds based on pool volatility
[ ] Set PREDICTIVE_IMPACT_THRESHOLD based on pool type
```
