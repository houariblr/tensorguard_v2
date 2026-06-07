# Remaining

## ✅ Done

### Core Math Engine
- [x] LiquidityTensor — 5D state (x, y, t, velocity, density)
- [x] Lyapunov metric — velocity energy ratio
- [x] Kolmogorov metric — price return z-score
- [x] Ricci metric — curvature deviation
- [x] Triple-gate detector (2/3 majority vote)
- [x] Simulation: attack detected at 78.8%, 0 false positives

### Anchor Program
- [x] GuardConfig — M/N multisig signer set
- [x] VoteAccount — accumulates daemon votes, auto-finalizes at threshold
- [x] PoolGuardState — daemon liveness tracking per pool
- [x] initialize() — deploy with signers + threshold
- [x] submit_vote() — daemon verdict, auto-finalize
- [x] post_aggregated() — Ed25519 FROST aggregated signature verification
- [x] guard_verify() — 3-path logic (safe / attack / fallback)
- [x] heartbeat() — daemon liveness signal
- [x] manage_signers() — add / remove / set_threshold

### Daemon
- [x] Config — env-based
- [x] PoolMonitor — confirmed state poller
- [x] MempoolMonitor — Jito stub + RPC fallback
- [x] Predictor — project pool state from pending swap
- [x] AttestationSender — submit_vote + post_aggregated transaction builder
- [x] Heartbeat sender
- [x] 2-phase main loop (confirmed + predictive)

### Security
- [x] Multisig daemon (Problem 1 — Honeypot)
- [x] Predictive attestation from mempool (Problem 2 — Latency)
- [x] DoS fallback + FallbackEvent (Problem 3 — DoS)

### On-chain Demo (Solana Devnet)
- [x] Program deployed: `5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG`
- [x] initialize() TX: `p9Dog...R4F4R6RktUzzeazW8Q1aBXnDeMYoG`
- [x] heartbeat() TX: Pool `FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg`
- [x] post_aggregated Safe TX: `3bQoia8H5D4uhSxJSSTeuQjWGStZB25n9vkJUrfu5tMc`
- [x] guard_verify PASS TX: `2kuVZxmGx4jGg9eeHhYvDnSbiPvJL5rSu3ERAtj1ezFB`
- [x] post_aggregated Attack TX: `2fQMzGBzj2XGxm8iNcqwudevK6CaE8YQvZqcm6XfTvvt`
- [x] guard_verify REVERT (AttackDetected): confirmed via simulation
- [x] guard_verify FALLBACK TX: `51ifHFjjJhPBXgFp2a3eM4NRPSsvjn3LXeb8VR9opsfe`

---

## 🔧 Remaining

### Problem 4 — False Positives (next)
- [ ] Monitoring-only mode (shadow mode — log without blocking)
- [ ] Volatility-aware thresholds (auto-scale during news events)
- [ ] Per-pool calibration from historical data

### Problem 5 — Adoption (after)
- [ ] Wrapper program — wraps immutable AMMs via CPI
- [ ] TypeScript SDK — single import for AMM integration

### Technical Debt
- [ ] Real Raydium pool layout parser (fix hardcoded byte offsets in monitor.rs)
- [ ] Jito gRPC wiring (tonic client in mempool.rs)
- [ ] Nonce persistence across daemon restarts
- [ ] Anchor tests (normal flow, attack blocked, stale, replay, fallback)

### Grant
- [x] Public GitHub repo
- [x] Live demo (devnet) — all 3 guard_verify paths verified on-chain
- [ ] AI subscription receipt ($200)
- [ ] Second tranche submission
