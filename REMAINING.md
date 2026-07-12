# TensorGuard — Remaining Work

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
- [x] guard_verify() — 3-path logic (PASS / REVERT / FALLBACK)
- [x] heartbeat() — daemon liveness signal
- [x] manage_signers() — add / remove / set_threshold

### Daemon
- [x] Config — env-based
- [x] PoolMonitor — confirmed state poller
- [x] MempoolMonitor — Jito stub + RPC fallback
- [x] Predictor — project pool state from pending swap
- [x] AttestationSender — submit_vote transaction builder
- [x] Heartbeat sender
- [x] 2-phase main loop (confirmed + predictive)

### Security Properties
- [x] Multisig daemon — M/N threshold, honeypot-resistant
- [x] Predictive attestation from mempool — low latency
- [x] DoS fallback + FallbackEvent — AMM stays live if daemon is silent

### Deployment
- [x] Deployed to Solana Devnet
- [x] Program ID: `5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG`
- [x] End-to-end demo: daemon → attestation → guard_verify (demo.js)
- [x] Public GitHub repo: https://github.com/houariblr/tensorguard_v2

---

## 🔧 Remaining

### Problem 4 — False Positives
- [ ] Monitoring-only / shadow mode (log without blocking)
- [ ] Volatility-aware thresholds (auto-scale during high-volatility events)
- [ ] Per-pool calibration from historical baseline data

### Problem 5 — Adoption
- [ ] Wrapper program — wraps immutable AMMs via CPI (no fork needed)
- [ ] TypeScript SDK — single import for AMM integration
- [ ] Integration guide for Raydium / Orca / Meteora

### Technical Debt
- [ ] Real Raydium pool layout parser (replace hardcoded byte offsets in monitor.rs)
- [ ] Jito gRPC wiring (tonic client in mempool.rs — currently stub)
- [ ] Nonce persistence across daemon restarts
- [ ] Anchor tests: normal flow, attack blocked, stale attestation, replay, fallback
- [ ] Remove shellexpand dependency from daemon Cargo.toml

### Roadmap
- [ ] Live demo URL with recorded video
- [ ] Mainnet deployment
- [ ] Multi-pool support (currently single pool per daemon instance)
- [ ] Dashboard UI (real-time threat feed)
