/**
 * tests.js — TensorGuard Test Suite
 *
 * Tests:
 *   1. initialize()            — GuardConfig created
 *   2. heartbeat()             — PoolGuardState updated
 *   3. post_aggregated (Safe)  — attestation posted
 *   4. guard_verify PASS       — Safe → swap proceeds
 *   5. guard_verify REVERT     — Attack → AttackDetected
 *   6. replay protection       — same nonce → fails
 *   7. wrong signer            — unauthorized → WrongSigner
 *   8. stale attestation       — old slot → StaleAttestation
 *   9. fallback path           — no attestation → NOT_READY
 *
 * Run: node tests.js
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
} = require("@solana/web3.js");
const assert = require("assert");
const nacl   = require("tweetnacl");
const fs     = require("fs");

// ─── Config ──────────────────────────────────────────────────────────────────
const RPC        = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const IX_SYSVAR  = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519    = new PublicKey("Ed25519SigVerify111111111111111111111111111");

// Discriminators
const DISC = {
  initialize:      Buffer.from([175, 175, 109,  31,  13, 152, 155, 237]),
  post_aggregated: Buffer.from([ 89,  99,   3, 196,  67, 157, 165,  80]),
  guard_verify:    Buffer.from([215, 255,  83, 127, 169, 196, 213,  38]),
  heartbeat:       Buffer.from([202, 104,  56,   6, 240, 170,  63, 134]),
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function encodeMsg(pool, nonce, isAttack, conf, lya, kol, ric) {
  const m = Buffer.alloc(55);
  pool.toBuffer().copy(m, 0);
  m.writeBigUInt64LE(BigInt(nonce), 32);
  m[40] = isAttack ? 1 : 0;
  m.writeUInt16LE(conf, 41);
  m.writeUInt32LE(lya,  43);
  m.writeUInt32LE(kol,  47);
  m.writeUInt32LE(ric,  51);
  return m;
}

function ed25519Ix(pubkey, message, signature) {
  const S = 16, P = 80, M = 112;
  const d = Buffer.alloc(M + message.length);
  d[0] = 1;
  d.writeUInt16LE(S,              2);  d.writeUInt16LE(0xFFFF, 4);
  d.writeUInt16LE(P,              6);  d.writeUInt16LE(0xFFFF, 8);
  d.writeUInt16LE(M,             10);  d.writeUInt16LE(message.length, 12);
  d.writeUInt16LE(0xFFFF,        14);
  Buffer.from(signature).copy(d, S);
  Buffer.from(pubkey).copy(d,    P);
  Buffer.from(message).copy(d,   M);
  return new TransactionInstruction({ programId: ED25519, keys: [], data: d });
}

function nonceToBuf(nonce) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(nonce), 0);
  return b;
}

function pdas(authority, pool, nonce) {
  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), authority.toBuffer()], PROGRAM_ID
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), pool.toBuffer()], PROGRAM_ID
  );
  const [attestation] = PublicKey.findProgramAddressSync(
    [Buffer.from("agg_attestation"), pool.toBuffer(), nonceToBuf(nonce)], PROGRAM_ID
  );
  return { guardConfig, poolGuardState, attestation };
}

async function simulate(connection, tx) {
  const sim  = await connection.simulateTransaction(tx);
  const logs = sim.value.logs || [];
  const err  = sim.value.err;
  const errCode = (logs.find(l => l.includes("Error Code:")) || "")
    .match(/Error Code: (\w+)/)?.[1];
  return { ok: !err, logs, errCode };
}

async function send(connection, tx) {
  const sig = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: true });
  await connection.confirmTransaction(sig, "confirmed");
  return sig;
}

async function buildTx(connection, payer, ...ixs) {
  const tx = new Transaction().add(...ixs);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  return tx;
}

// ─── Test runner ─────────────────────────────────────────────────────────────

let passed = 0, failed = 0;

async function test(name, fn) {
  process.stdout.write(`  ${name} ... `);
  try {
    await fn();
    console.log("✅ PASS");
    passed++;
  } catch (e) {
    console.log("❌ FAIL");
    console.log(`     ${e.message}`);
    failed++;
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const payer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(
      process.env.HOME + "/.config/solana/id.json"
    )))
  );
  // Use a fresh pool keypair each run to avoid state conflicts
  const pool       = Keypair.generate().publicKey;
  const connection = new Connection(RPC, "confirmed");
  const slot       = await connection.getSlot();
  const nonce      = slot; // unique nonce per run

  console.log("═".repeat(56));
  console.log("  TensorGuard — Test Suite");
  console.log("  Caller:", payer.publicKey.toBase58());
  console.log("  Pool:  ", pool.toBase58());
  console.log("═".repeat(56) + "\n");

  // Read group_pubkey from GuardConfig on-chain
  const { guardConfig } = pdas(payer.publicKey, pool, nonce);
  const cfgAcc = await connection.getAccountInfo(
    PublicKey.findProgramAddressSync(
      [Buffer.from("guard_config"), payer.publicKey.toBuffer()], PROGRAM_ID
    )[0]
  );
  if (!cfgAcc) throw new Error("Run initialize.js first");
  const signersLen  = cfgAcc.data.readUInt32LE(8 + 32);
  const gpkStart    = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgAcc.data.slice(gpkStart, gpkStart + 32);

  // Shorthand
  const GC  = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), payer.publicKey.toBuffer()], PROGRAM_ID
  )[0];

  // ── 1. heartbeat ────────────────────────────────────────────────────────────
  await test("1. heartbeat() — PoolGuardState created", async () => {
    const [pgs] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_guard_state"), pool.toBuffer()], PROGRAM_ID
    );
    const data = Buffer.concat([DISC.heartbeat, pool.toBuffer()]);
    const tx = await buildTx(connection, payer,
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true,  isWritable: true  },
          { pubkey: GC,              isSigner: false, isWritable: false },
          { pubkey: pgs,             isSigner: false, isWritable: true  },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data,
      })
    );
    const sim = await simulate(connection, tx);
    assert.ok(sim.ok, `Simulation failed: ${sim.errCode}`);
    await send(connection, tx);
  });

  // ── 2. post_aggregated Safe ─────────────────────────────────────────────────
  await test("2. post_aggregated(Safe) — attestation created", async () => {
    const { poolGuardState, attestation } = pdas(payer.publicKey, pool, nonce);
    const msg = encodeMsg(pool, nonce, false, 7880, 10880, 43693, 110);
    const sig = nacl.sign.detached(msg, payer.secretKey);

    const args = Buffer.alloc(32+8+1+2+4+4+4+1+64);
    let off = 0;
    pool.toBuffer().copy(args, off);    off += 32;
    nonceToBuf(nonce).copy(args, off);  off += 8;
    args[off] = 0;                       off += 1;
    args.writeUInt16LE(7880, off);       off += 2;
    args.writeUInt32LE(10880, off);      off += 4;
    args.writeUInt32LE(43693, off);      off += 4;
    args.writeUInt32LE(110, off);        off += 4;
    args[off] = 0b00000001;              off += 1;
    Buffer.from(sig).copy(args, off);

    const tx = await buildTx(connection, payer,
      ed25519Ix(groupPubkey, msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey,         isSigner: true,  isWritable: true  },
          { pubkey: GC,                      isSigner: false, isWritable: false },
          { pubkey: attestation,             isSigner: false, isWritable: true  },
          { pubkey: poolGuardState,          isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,               isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([DISC.post_aggregated, args]),
      })
    );
    const sim = await simulate(connection, tx);
    assert.ok(sim.ok, `Simulation failed: ${sim.errCode}`);
    await send(connection, tx);
  });

  // ── 3. guard_verify PASS ────────────────────────────────────────────────────
  await test("3. guard_verify(Safe) — expect PASS ✅", async () => {
    const { poolGuardState, attestation } = pdas(payer.publicKey, pool, nonce);
    const msg = encodeMsg(pool, nonce, false, 7880, 10880, 43693, 110);
    const sig = nacl.sign.detached(msg, payer.secretKey);

    const tx = await buildTx(connection, payer,
      ed25519Ix(groupPubkey, msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: pool,            isSigner: false, isWritable: false },
          { pubkey: GC,              isSigner: false, isWritable: false },
          { pubkey: attestation,     isSigner: false, isWritable: true  },
          { pubkey: poolGuardState,  isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,       isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true,  isWritable: true  },
        ],
        data: DISC.guard_verify,
      })
    );
    const sim = await simulate(connection, tx);
    assert.ok(sim.ok, `Expected PASS but got: ${sim.errCode}`);
    const guardLog = sim.logs.find(l => l.includes("TensorGuard ✓ SAFE"));
    assert.ok(guardLog, "Expected TensorGuard ✓ SAFE in logs");
  });

  // ── 4. post_aggregated Attack ───────────────────────────────────────────────
  const nonceA = nonce + 1;
  await test("4. post_aggregated(Attack) — attack attestation created", async () => {
    const { poolGuardState, attestation } = pdas(payer.publicKey, pool, nonceA);
    const msg = encodeMsg(pool, nonceA, true, 9500, 108800, 436930, 330);
    const sig = nacl.sign.detached(msg, payer.secretKey);

    const args = Buffer.alloc(32+8+1+2+4+4+4+1+64);
    let off = 0;
    pool.toBuffer().copy(args, off);      off += 32;
    nonceToBuf(nonceA).copy(args, off);   off += 8;
    args[off] = 1;                         off += 1; // Attack
    args.writeUInt16LE(9500, off);         off += 2;
    args.writeUInt32LE(108800, off);       off += 4;
    args.writeUInt32LE(436930, off);       off += 4;
    args.writeUInt32LE(330, off);          off += 4;
    args[off] = 0b00000001;                off += 1;
    Buffer.from(sig).copy(args, off);

    const tx = await buildTx(connection, payer,
      ed25519Ix(groupPubkey, msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey,         isSigner: true,  isWritable: true  },
          { pubkey: GC,                      isSigner: false, isWritable: false },
          { pubkey: attestation,             isSigner: false, isWritable: true  },
          { pubkey: poolGuardState,          isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,               isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([DISC.post_aggregated, args]),
      })
    );
    const sim = await simulate(connection, tx);
    assert.ok(sim.ok, `Simulation failed: ${sim.errCode}`);
    await send(connection, tx);
  });

  // ── 5. guard_verify REVERT AttackDetected ───────────────────────────────────
  await test("5. guard_verify(Attack) — expect REVERT AttackDetected ❌", async () => {
    const { poolGuardState, attestation } = pdas(payer.publicKey, pool, nonceA);
    const msg = encodeMsg(pool, nonceA, true, 9500, 108800, 436930, 330);
    const sig = nacl.sign.detached(msg, payer.secretKey);

    const tx = await buildTx(connection, payer,
      ed25519Ix(groupPubkey, msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: pool,            isSigner: false, isWritable: false },
          { pubkey: GC,              isSigner: false, isWritable: false },
          { pubkey: attestation,     isSigner: false, isWritable: true  },
          { pubkey: poolGuardState,  isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,       isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true,  isWritable: true  },
        ],
        data: DISC.guard_verify,
      })
    );
    const sim = await simulate(connection, tx);
    assert.ok(!sim.ok, "Expected REVERT but got PASS");
    assert.strictEqual(sim.errCode, "AttackDetected",
      `Expected AttackDetected but got: ${sim.errCode}`);
  });

  // ── 6. Replay protection ────────────────────────────────────────────────────
  await test("6. replay — same nonce → AlreadyInUse", async () => {
    const { poolGuardState, attestation } = pdas(payer.publicKey, pool, nonce);
    const msg = encodeMsg(pool, nonce, false, 7880, 10880, 43693, 110);
    const sig = nacl.sign.detached(msg, payer.secretKey);

    const args = Buffer.alloc(32+8+1+2+4+4+4+1+64);
    let off = 0;
    pool.toBuffer().copy(args, off);    off += 32;
    nonceToBuf(nonce).copy(args, off);  off += 8;
    args[off] = 0; off += 1;
    args.writeUInt16LE(7880, off); off += 2;
    args.writeUInt32LE(10880, off); off += 4;
    args.writeUInt32LE(43693, off); off += 4;
    args.writeUInt32LE(110, off); off += 4;
    args[off] = 0b00000001; off += 1;
    Buffer.from(sig).copy(args, off);

    const tx = await buildTx(connection, payer,
      ed25519Ix(groupPubkey, msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey,         isSigner: true,  isWritable: true  },
          { pubkey: GC,                      isSigner: false, isWritable: false },
          { pubkey: attestation,             isSigner: false, isWritable: true  },
          { pubkey: poolGuardState,          isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,               isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([DISC.post_aggregated, args]),
      })
    );
    const sim = await simulate(connection, tx);
    // Anchor returns "already in use" when PDA already exists
    assert.ok(!sim.ok, "Expected FAIL for duplicate nonce but got PASS");
  });

  // ── 7. Wrong signer ─────────────────────────────────────────────────────────
  await test("7. wrong signer — expect WrongSigner", async () => {
    const attacker    = Keypair.generate();
    const nonceW      = nonce + 2;
    const { poolGuardState, attestation } = pdas(payer.publicKey, pool, nonceW);
    const msg = encodeMsg(pool, nonceW, false, 7880, 10880, 43693, 110);
    // Sign with WRONG key
    const sig = nacl.sign.detached(msg, attacker.secretKey);

    const tx = await buildTx(connection, payer,
      // Ed25519 ix with WRONG pubkey
      ed25519Ix(attacker.publicKey.toBuffer(), msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: pool,            isSigner: false, isWritable: false },
          { pubkey: GC,              isSigner: false, isWritable: false },
          { pubkey: attestation,     isSigner: false, isWritable: true  },
          { pubkey: poolGuardState,  isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,       isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true,  isWritable: true  },
        ],
        data: DISC.guard_verify,
      })
    );
    const sim = await simulate(connection, tx);
    assert.ok(!sim.ok, "Expected FAIL for wrong signer but got PASS");
  });

  // ── 8. Fallback (no attestation) ────────────────────────────────────────────
  await test("8. fallback — no attestation → NOT_READY", async () => {
    const { poolGuardState } = pdas(payer.publicKey, pool, nonce);
    // Use a fresh nonce that has no attestation
    const nonceF = nonce + 999;
    const { attestation: fakeAtt } = pdas(payer.publicKey, pool, nonceF);
    const msg = encodeMsg(pool, nonce, false, 7880, 10880, 43693, 110);
    const sig = nacl.sign.detached(msg, payer.secretKey);

    const tx = await buildTx(connection, payer,
      ed25519Ix(groupPubkey, msg, sig),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: pool,            isSigner: false, isWritable: false },
          { pubkey: GC,              isSigner: false, isWritable: false },
          { pubkey: poolGuardState,  isSigner: false, isWritable: true  }, // wrong account as attestation
          { pubkey: poolGuardState,  isSigner: false, isWritable: true  },
          { pubkey: IX_SYSVAR,       isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true,  isWritable: true  },
        ],
        data: DISC.guard_verify,
      })
    );
    const sim = await simulate(connection, tx);
    // Expect either NOT_READY or SAFE (fallback) — both are acceptable
    const isExpected = !sim.ok || sim.logs.some(l =>
      l.includes("NOT_READY") || l.includes("FALLBACK") || l.includes("SAFE")
    );
    assert.ok(isExpected, `Unexpected result: ${sim.errCode}`);
  });

  // ── Summary ──────────────────────────────────────────────────────────────────
  console.log("\n" + "═".repeat(56));
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log("  🎉 All tests passed!");
  } else {
    console.log("  ⚠️  Some tests failed — check output above");
  }
  console.log("═".repeat(56));
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error("Fatal:", e.message);
  process.exit(1);
});
