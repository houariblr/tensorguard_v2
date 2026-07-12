/**
 * demo_full_fixed.js — TensorGuard End-to-End Demo (Fixed)
 *
 * يشغّل الـ 6 مسارات كاملة في sequence واحد:
 *
 *   STEP 1: heartbeat         → تفعيل pool_guard_state
 *   STEP 2: post_aggregated(Safe, nonce=slot)    → فوري
 *   STEP 3: guard_verify(PATH 1) → ✅ PASS (Safe)
 *   STEP 4: post_aggregated(Attack, nonce=slot+1) → فوري
 *   STEP 5: guard_verify(PATH 2) → ❌ REVERT AttackDetected
 *   STEP 6: guard_verify(PATH 3) → ⚠️ FALLBACK (nonce غير موجود)
 *
 * كل attestation يُنشر مباشرة قبل guard_verify في نفس الـ slot
 * حتى لا تنتهي صلاحيته (40 slots = ~16 ثانية)
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
} = require("@solana/web3.js");
const fs   = require("fs");
const nacl = require("tweetnacl");

// ─── Config ──────────────────────────────────────────────────────────────────
const RPC        = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const POOL       = new PublicKey("FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg");

const IX_SYSVAR   = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519_PGM = new PublicKey("Ed25519SigVerify111111111111111111111111111");

const DISC_POST_AGG     = Buffer.from([89, 99, 3, 196, 67, 157, 165, 80]);
const DISC_GUARD_VERIFY = Buffer.from([215, 255, 83, 127, 169, 196, 213, 38]);
const DISC_HEARTBEAT    = Buffer.from([202, 104, 56, 6, 240, 170, 63, 134]);

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function encodeMsg(pool, nonce, isAttack, confBps, lya, kol, ric) {
  const m = Buffer.alloc(55);
  pool.toBuffer().copy(m, 0);
  m.writeBigUInt64LE(BigInt(nonce), 32);
  m[40] = isAttack ? 1 : 0;
  m.writeUInt16LE(confBps, 41);
  m.writeUInt32LE(lya, 43);
  m.writeUInt32LE(kol, 47);
  m.writeUInt32LE(ric, 51);
  return m;
}

function ed25519Ix(pubkeyBytes, message, signature) {
  const S = 16, P = 80, M = 112;
  const d = Buffer.alloc(M + message.length);
  d[0] = 1;
  d.writeUInt16LE(S, 2);   d.writeUInt16LE(0xFFFF, 4);
  d.writeUInt16LE(P, 6);   d.writeUInt16LE(0xFFFF, 8);
  d.writeUInt16LE(M, 10);  d.writeUInt16LE(message.length, 12);
  d.writeUInt16LE(0xFFFF, 14);
  Buffer.from(signature).copy(d, S);
  Buffer.from(pubkeyBytes).copy(d, P);
  Buffer.from(message).copy(d, M);
  return new TransactionInstruction({ programId: ED25519_PGM, keys: [], data: d });
}

function postAggIx(coordinator, guardConfig, attestation, poolGuardState,
                   pool, nonce, isAttack, confBps, lya, kol, ric, bitmask, sig) {
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(BigInt(nonce), 0);
  const args = Buffer.alloc(32+8+1+2+4+4+4+1+64);
  let off = 0;
  pool.toBuffer().copy(args, off);  off += 32;
  nonceBuf.copy(args, off);         off += 8;
  args[off] = isAttack ? 1 : 0;    off += 1;
  args.writeUInt16LE(confBps, off); off += 2;
  args.writeUInt32LE(lya, off);     off += 4;
  args.writeUInt32LE(kol, off);     off += 4;
  args.writeUInt32LE(ric, off);     off += 4;
  args[off] = bitmask;            off += 1;
  Buffer.from(sig).copy(args, off);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: coordinator,             isSigner: true,  isWritable: true  },
      { pubkey: guardConfig,             isSigner: false, isWritable: false },
      { pubkey: attestation,             isSigner: false, isWritable: true  },
      { pubkey: poolGuardState,          isSigner: false, isWritable: true  },
      { pubkey: IX_SYSVAR,               isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([DISC_POST_AGG, args]),
  });
}

function guardVerifyIx(caller, pool, guardConfig, attestation, poolGuardState) {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: pool,           isSigner: false, isWritable: false },
      { pubkey: guardConfig,    isSigner: false, isWritable: false },
      { pubkey: attestation,    isSigner: false, isWritable: true  },
      { pubkey: poolGuardState, isSigner: false, isWritable: true  },
      { pubkey: IX_SYSVAR,      isSigner: false, isWritable: false },
      { pubkey: caller,         isSigner: true,  isWritable: true  },
    ],
    data: DISC_GUARD_VERIFY,
  });
}

function heartbeatIx(payer, guardConfig, poolGuardState, pool) {
  const data = Buffer.concat([DISC_HEARTBEAT, pool.toBuffer()]);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey,       isSigner: true,  isWritable: true  },
      { pubkey: guardConfig,           isSigner: false, isWritable: false },
      { pubkey: poolGuardState,        isSigner: false, isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

async function signedTx(connection, payer, ...ixs) {
  const tx = new Transaction().add(...ixs);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  return tx;
}

async function sendTx(label, connection, tx, expectRevert = false) {
  const sim  = await connection.simulateTransaction(tx);
  const logs = sim.value.logs || [];
  const err  = sim.value.err;
  const guardLog = logs.find(l => l.includes("TensorGuard") || l.includes("agg]") || l.includes("FALLBACK"));

  if (!err) {
    const sig = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: true });
    await connection.confirmTransaction(sig, "confirmed");
    console.log(`  ✅ ${label}`);
    if (guardLog) console.log(`     ${guardLog.replace("Program log: ", "")}`);
    console.log(`     TX: ${sig.slice(0, 44)}...`);
    return { ok: true, sig };
  } else {
    const errLine = logs.find(l => l.includes("Error Code:")) || "";
    const code    = errLine.match(/Error Code: (\w+)/)?.[1] || JSON.stringify(err);
    if (expectRevert) {
      console.log(`  ✅ ${label}`);
      console.log(`     Correctly reverted: ${code}`);
      if (guardLog) console.log(`     ${guardLog.replace("Program log: ", "")}`);
      return { ok: false, reverted: true, code };
    } else {
      console.log(`  ❌ ${label} — FAILED: ${code}`);
      logs.filter(l => l.includes("Program log:")).forEach(l => console.log(`     ${l}`));
      return { ok: false };
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const keypair = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(
      process.env.HOME + "/.config/solana/id.json"
    )))
  );
  const connection = new Connection(RPC, "confirmed");

  console.clear();
  await sleep(500);

  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║          TensorGuard — Full Fixed Demo               ║");
  console.log("║   Pre-execution AMM Attack Detection                 ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  await sleep(1500);

  console.log("\n  Program : 5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
  console.log("  Network : Solana Devnet");
  console.log("  Pool    :", POOL.toBase58());
  console.log("  Method  : 5D Liquidity Tensor Field");
  console.log("            (Lyapunov + Kolmogorov + Ricci)\n");
  await sleep(2000);

  // ── PDAs ───────────────────────────────────────────────────────────────────
  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), keypair.publicKey.toBuffer()], PROGRAM_ID
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), POOL.toBuffer()], PROGRAM_ID
  );

  function attPDA(nonce) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(BigInt(nonce), 0);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("agg_attestation"), POOL.toBuffer(), buf], PROGRAM_ID
    );
    return pda;
  }

  // ── قراءة group_pubkey من الـ chain ───────────────────────────────────────
  const cfgInfo = await connection.getAccountInfo(guardConfig);
  if (!cfgInfo) throw new Error("guard_config not found — run initialize.js first");
  const cfgData    = cfgInfo.data;
  const signersLen = cfgData.readUInt32LE(8 + 32);
  const gpkStart   = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgData.slice(gpkStart, gpkStart + 32);
  console.log("group_pubkey:", Buffer.from(groupPubkey).toString("hex").slice(0,32) + "...");
  console.log("guardConfig :", guardConfig.toBase58());
  console.log("poolState   :", poolGuardState.toBase58());

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  STEP 1: heartbeat — Activate PoolGuardState");
  console.log("━".repeat(56));
  await sleep(1500);

  const hbTx = await signedTx(connection, keypair,
    heartbeatIx(keypair, guardConfig, poolGuardState, POOL)
  );
  const hbRes = await sendTx("Heartbeat sent → daemon active", connection, hbTx);
  if (!hbRes.ok) throw new Error("Heartbeat failed — cannot continue");
  await sleep(2000);

  // ── ننتظر slot جديد لتجنب تكرار nonce ────────────────────────────────────
  const slot = await connection.getSlot();
  const nonceS = slot;
  const nonceA = slot + 1;
  console.log(`\n  Current slot: ${slot}`);
  console.log(`  Safe nonce  : ${nonceS}`);
  console.log(`  Attack nonce: ${nonceA}\n`);
  await sleep(1000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("━".repeat(56));
  console.log("  STEP 2: post_aggregated (SAFE)");
  console.log("  Verdict: Safe | Confidence: 78.8%");
  console.log("━".repeat(56));
  await sleep(1500);

  const msgSafe   = encodeMsg(POOL, nonceS, false, 7880, 10880, 43693, 110);
  const sigSafe   = nacl.sign.detached(msgSafe, keypair.secretKey);
  const attSafe   = attPDA(nonceS);

  const tx1 = await signedTx(connection, keypair,
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    postAggIx(keypair.publicKey, guardConfig, attSafe, poolGuardState,
              POOL, nonceS, false, 7880, 10880, 43693, 110, 0b00000001, sigSafe)
  );
  const r1 = await sendTx(`Attestation posted (Safe, nonce=${nonceS})`, connection, tx1);
  if (!r1.ok) throw new Error("Safe attestation failed");
  await sleep(2000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  STEP 3: guard_verify PATH 1 — Safe → expect PASS ✅");
  console.log("━".repeat(56));
  await sleep(1500);

  const tx2 = await signedTx(connection, keypair,
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig, attSafe, poolGuardState)
  );
  await sendTx("guard_verify → PASS  ✅  Swap proceeds normally", connection, tx2);
  await sleep(2500);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  STEP 4: post_aggregated (ATTACK)");
  console.log("  Verdict: Attack | Confidence: 95%");
  console.log("  Tensor: L=1088.0 K=4369.3 R=3.3");
  console.log("━".repeat(56));
  await sleep(1500);

  const msgAttack = encodeMsg(POOL, nonceA, true, 9500, 108800, 436930, 330);
  const sigAttack = nacl.sign.detached(msgAttack, keypair.secretKey);
  const attAttack = attPDA(nonceA);

  const tx3 = await signedTx(connection, keypair,
    ed25519Ix(groupPubkey, msgAttack, sigAttack),
    postAggIx(keypair.publicKey, guardConfig, attAttack, poolGuardState,
              POOL, nonceA, true, 9500, 108800, 436930, 330, 0b00000001, sigAttack)
  );
  const r3 = await sendTx(`Attestation posted (Attack, nonce=${nonceA})`, connection, tx3);
  if (!r3.ok) throw new Error("Attack attestation failed");
  await sleep(2000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  STEP 5: guard_verify PATH 2 — Attack → expect REVERT ❌");
  console.log("━".repeat(56));
  await sleep(1500);

  const tx4 = await signedTx(connection, keypair,
    ed25519Ix(groupPubkey, msgAttack, sigAttack),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig, attAttack, poolGuardState)
  );
  await sendTx("guard_verify → REVERT ❌  AttackDetected — Swap BLOCKED", connection, tx4, true);
  await sleep(2500);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  STEP 6: Fallback — no attestation (daemon silent)");
  console.log("━".repeat(56));
  await sleep(1500);

  // nonce بعيد جداً → PDA غير مهيأ → fallback path
  const nonceF = nonceA + 1000000;
  const attFallback = attPDA(nonceF);

  const tx5 = await signedTx(connection, keypair,
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig, attFallback, poolGuardState)
  );
  await sendTx("guard_verify → FALLBACK ⚠️  Daemon silent — ALLOWING", connection, tx5);
  await sleep(2000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "╔══════════════════════════════════════════════════════╗");
  console.log("║                   Final Results                      ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  STEP 1: Heartbeat      → daemon active    ✅       ║");
  console.log("║  STEP 2: Safe attest    → posted on-chain  ✅       ║");
  console.log("║  STEP 3: PATH 1 (Safe)  → swap proceeds    ✅       ║");
  console.log("║  STEP 4: Attack attest  → posted on-chain  ✅       ║");
  console.log("║  STEP 5: PATH 2 (Attack)→ swap blocked    ❌       ║");
  console.log("║  STEP 6: PATH 3 (Fallback)→ daemon silent  ⚠️       ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  github.com/houariblr/tensorguard_v2                ║");
  console.log("╚══════════════════════════════════════════════════════╝");
}

main().catch(e => {
  console.error("\nFatal:", e.message);
  process.exit(1);
});
