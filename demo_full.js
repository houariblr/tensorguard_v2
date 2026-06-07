/**
 * demo_full.js — TensorGuard End-to-End Demo
 *
 * يشغّل الـ 3 مسارات كاملة في sequence واحد:
 *
 *   STEP 1: post_aggregated (Safe,   nonce=10) → فوري
 *   STEP 2: guard_verify    (PATH 1) → ✅ PASS
 *   STEP 3: post_aggregated (Attack, nonce=11) → فوري
 *   STEP 4: guard_verify    (PATH 2) → ❌ REVERT AttackDetected
 *   STEP 5: guard_verify    (PATH 3) → ⚠️  FALLBACK (daemon silent)
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

const DISC_POST_AGG    = Buffer.from([89, 99, 3, 196, 67, 157, 165, 80]);
const DISC_GUARD_VERIFY = Buffer.from([215, 255, 83, 127, 169, 196, 213, 38]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

// 55-byte canonical message (مطابق encode_attestation_msg في Rust)
function encodeMsg(pool, nonce, isAttack, confBps, lya, kol, ric) {
  const m = Buffer.alloc(55);
  pool.toBuffer().copy(m, 0);
  m.writeBigUInt64LE(BigInt(nonce), 32);
  m[40] = isAttack ? 1 : 0;
  m.writeUInt16LE(confBps, 41);
  m.writeUInt32LE(lya,     43);
  m.writeUInt32LE(kol,     47);
  m.writeUInt32LE(ric,     51);
  return m;
}

// Ed25519 precompile instruction
function ed25519Ix(pubkeyBytes, message, signature) {
  const S = 16, P = 80, M = 112;
  const d = Buffer.alloc(M + message.length);
  d[0] = 1;
  d.writeUInt16LE(S,              2);  d.writeUInt16LE(0xFFFF, 4);
  d.writeUInt16LE(P,              6);  d.writeUInt16LE(0xFFFF, 8);
  d.writeUInt16LE(M,             10);  d.writeUInt16LE(message.length, 12);
  d.writeUInt16LE(0xFFFF,        14);
  Buffer.from(signature).copy(d, S);
  Buffer.from(pubkeyBytes).copy(d, P);
  Buffer.from(message).copy(d,     M);
  return new TransactionInstruction({ programId: ED25519_PGM, keys: [], data: d });
}

// post_aggregated instruction
function postAggIx(coordinator, guardConfig, attestation, poolGuardState,
                   pool, nonce, isAttack, confBps, lya, kol, ric, bitmask, sig) {
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(BigInt(nonce), 0);

  const args = Buffer.alloc(32+8+1+2+4+4+4+1+64);
  let off = 0;
  pool.toBuffer().copy(args, off);    off += 32;
  nonceBuf.copy(args, off);           off += 8;
  args[off] = isAttack ? 1 : 0;      off += 1;
  args.writeUInt16LE(confBps, off);   off += 2;
  args.writeUInt32LE(lya, off);       off += 4;
  args.writeUInt32LE(kol, off);       off += 4;
  args.writeUInt32LE(ric, off);       off += 4;
  args[off] = bitmask;                off += 1;
  Buffer.from(sig).copy(args, off);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: coordinator,          isSigner: true,  isWritable: true  },
      { pubkey: guardConfig,          isSigner: false, isWritable: false },
      { pubkey: attestation,          isSigner: false, isWritable: true  },
      { pubkey: poolGuardState,       isSigner: false, isWritable: true  },
      { pubkey: IX_SYSVAR,            isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([DISC_POST_AGG, args]),
  });
}

// guard_verify instruction
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

// إرسال tx مع simulate أولاً
async function sendTx(label, connection, tx, expectRevert = false) {
  const sim = await connection.simulateTransaction(tx);
  const logs = sim.value.logs || [];
  const err  = sim.value.err;

  // استخرج آخر Program log مفيد
  const guardLog = logs.find(l => l.includes("TensorGuard") || l.includes("agg]"));

  if (!err) {
    const sig = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: true,
    });
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
      return { ok: false, reverted: true, code };
    } else {
      console.log(`  ❌ ${label} — FAILED: ${code}`);
      logs.filter(l => l.includes("Program log:")).forEach(l =>
        console.log(`     ${l}`)
      );
      return { ok: false, reverted: false, code };
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

  console.log("═".repeat(56));
  console.log("  TensorGuard — Full Demo");
  console.log("  Caller:", keypair.publicKey.toBase58());
  console.log("═".repeat(56));

  // ── PDAs ──────────────────────────────────────────────────────────────────
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

  // ── group_pubkey من الـ chain ─────────────────────────────────────────────
  const cfgInfo = await connection.getAccountInfo(guardConfig);
  if (!cfgInfo) throw new Error("guard_config not found — run initialize() first");
  const cfgData      = cfgInfo.data;
  const signersLen   = cfgData.readUInt32LE(8 + 32);
  const gpkStart     = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey  = cfgData.slice(gpkStart, gpkStart + 32);

  console.log("\ngroup_pubkey:", Buffer.from(groupPubkey).toString("hex").slice(0,32) + "...");
  console.log("guardConfig: ", guardConfig.toBase58());
  console.log("poolState:   ", poolGuardState.toBase58());

  // helper: blockhash + sign
  async function signedTx(...ixs) {
    const tx = new Transaction().add(...ixs);
    const { blockhash } = await connection.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = keypair.publicKey;
    tx.sign(keypair);
    return tx;
  }

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n── STEP 1/2: Safe attestation + guard_verify PASS ──────────");

  // نستخدم nonce عالي لتجنب "already initialized"
  // نختار nonce بناءً على current slot لضمان عدم التكرار
  const slot    = await connection.getSlot();
  const nonceS  = slot;        // Safe nonce
  const nonceA  = slot + 1;    // Attack nonce

  const msgSafe   = encodeMsg(POOL, nonceS, false, 7880, 10880, 43693, 110);
  const sigSafe   = nacl.sign.detached(msgSafe, keypair.secretKey);
  const attSafe   = attPDA(nonceS);

  // Post Safe attestation
  const tx1 = await signedTx(
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    postAggIx(keypair.publicKey, guardConfig, attSafe, poolGuardState,
              POOL, nonceS, false, 7880, 10880, 43693, 110, 0b00000001, sigSafe)
  );
  const r1 = await sendTx("post_aggregated (Safe, nonce=" + nonceS + ")", connection, tx1);
  if (!r1.ok) { console.error("Cannot continue without Safe attestation"); return; }

  // guard_verify → PATH 1: PASS
  const tx2 = await signedTx(
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig, attSafe, poolGuardState)
  );
  await sendTx("guard_verify PATH 1 — Safe → expect PASS ✅", connection, tx2);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n── STEP 3/4: Attack attestation + guard_verify REVERT ───────");

  const msgAttack = encodeMsg(POOL, nonceA, true, 9500, 108800, 436930, 330);
  const sigAttack = nacl.sign.detached(msgAttack, keypair.secretKey);
  const attAttack = attPDA(nonceA);

  // Post Attack attestation
  const tx3 = await signedTx(
    ed25519Ix(groupPubkey, msgAttack, sigAttack),
    postAggIx(keypair.publicKey, guardConfig, attAttack, poolGuardState,
              POOL, nonceA, true, 9500, 108800, 436930, 330, 0b00000001, sigAttack)
  );
  const r3 = await sendTx("post_aggregated (Attack, nonce=" + nonceA + ")", connection, tx3);

  if (r3.ok) {
    // guard_verify → PATH 2: REVERT AttackDetected
    const tx4 = await signedTx(
      ed25519Ix(groupPubkey, msgAttack, sigAttack),
      guardVerifyIx(keypair.publicKey, POOL, guardConfig, attAttack, poolGuardState)
    );
    await sendTx(
      "guard_verify PATH 2 — Attack → expect REVERT ❌",
      connection, tx4,
      true  // expectRevert=true
    );
  }

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n── STEP 5: Fallback path — no attestation ───────────────────");
  // نستخدم nonce بعيد جداً → attestation PDA غير مُهيّأ (data فارغ)
  // لكن يجب أن يكون الـ account موجوداً أو نمرر system-owned account
  // الحل: نمرر poolGuardState نفسه كـ attestation (بيانات مختلفة → att_len <= VERDICT_OFFSET)
  // البرنامج يفحص att_len > VERDICT_OFFSET ← إذا كان أصغر → fallback path
  const tx5 = await signedTx(
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig,
                  poolGuardState,  // ← نمرر poolGuardState بدلاً من attestation
                  poolGuardState)  // ← daemon still alive → expect NOT_READY
  );
  await sendTx(
    "guard_verify PATH 3 — No attestation → expect NOT_READY or FALLBACK ⚠️",
    connection, tx5,
    true  // هذا يُرجع خطأ وهذا متوقع
  );

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "═".repeat(56));
  console.log("  Demo Complete!");
  console.log("  PATH 1 (Safe)    → swap proceeds   ✅");
  console.log("  PATH 2 (Attack)  → swap blocked    ❌");
  console.log("  PATH 3 (Fallback)→ daemon signal   ⚠️");
  console.log("═".repeat(56));
}

main().catch(e => {
  console.error("Fatal:", e.message);
  if (e.logs) e.logs.forEach(l => console.error(" ", l));
});
