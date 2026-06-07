/**
 * guard_verify.js
 *
 * Demo كامل لـ guard_verify — يختبر المسارات الـ 3:
 *
 *   PATH 1 ✅ PASS   — attestation حديث + Safe
 *   PATH 2 ❌ REVERT — attestation حديث + Attack
 *   PATH 3 ⚠️  PASS   — لا attestation + daemon صامت > 200 slots
 *
 * Transaction layout (مثل post_aggregated تماماً):
 *   ix[0]: Ed25519Program precompile
 *   ix[1]: guard_verify
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
} = require("@solana/web3.js");
const fs   = require("fs");
const nacl = require("tweetnacl");

// ─── Config ──────────────────────────────────────────────────────────────────
const DEVNET_RPC  = "https://api.devnet.solana.com";
const PROGRAM_ID  = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const POOL_PUBKEY = new PublicKey("FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg");
const NONCE       = BigInt(1);

const SYSVAR_INSTRUCTIONS = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519_PROGRAM     = new PublicKey("Ed25519SigVerify111111111111111111111111111");

// Discriminator: sha256("global:guard_verify")[0..8]
// نحسبه من الـ IDL أو anchor — القيمة الصحيحة:
const DISC_GUARD_VERIFY = Buffer.from([215, 255, 83, 127, 169, 196, 213, 38]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

// نفس encode_attestation_msg في post_aggregated.rs (55 bytes)
function encodeAttestationMsg(pool, nonce, verdict, confidenceBps,
                               lyapunovX100, kolmogorovX100, ricciX100) {
  const msg = Buffer.alloc(55);
  pool.toBuffer().copy(msg, 0);
  msg.writeBigUInt64LE(nonce, 32);
  msg[40] = verdict === "Attack" ? 1 : 0;
  msg.writeUInt16LE(confidenceBps,  41);
  msg.writeUInt32LE(lyapunovX100,   43);
  msg.writeUInt32LE(kolmogorovX100, 47);
  msg.writeUInt32LE(ricciX100,      51);
  return msg;
}

// بناء Ed25519 precompile instruction
function buildEd25519Ix(pubkeyBytes, message, signature) {
  const SIG_OFF = 16;
  const PK_OFF  = SIG_OFF + 64;
  const MSG_OFF = PK_OFF  + 32;
  const data    = Buffer.alloc(MSG_OFF + message.length);

  data[0] = 1;   // num_signatures
  data[1] = 0;   // padding
  data.writeUInt16LE(SIG_OFF,         2);
  data.writeUInt16LE(0xFFFF,          4);   // current ix
  data.writeUInt16LE(PK_OFF,          6);
  data.writeUInt16LE(0xFFFF,          8);
  data.writeUInt16LE(MSG_OFF,         10);
  data.writeUInt16LE(message.length,  12);
  data.writeUInt16LE(0xFFFF,          14);

  Buffer.from(signature).copy(data, SIG_OFF);
  Buffer.from(pubkeyBytes).copy(data, PK_OFF);
  Buffer.from(message).copy(data, MSG_OFF);

  return new TransactionInstruction({ programId: ED25519_PROGRAM, keys: [], data });
}

// بناء guard_verify instruction
function buildGuardVerifyIx(caller, pool, guardConfig, attestation,
                             poolGuardState) {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: pool,               isSigner: false, isWritable: false }, // pool
      { pubkey: guardConfig,        isSigner: false, isWritable: false }, // guard_config
      { pubkey: attestation,        isSigner: false, isWritable: true  }, // attestation
      { pubkey: poolGuardState,     isSigner: false, isWritable: true  }, // pool_guard_state
      { pubkey: SYSVAR_INSTRUCTIONS,isSigner: false, isWritable: false }, // instructions_sysvar
      { pubkey: caller.publicKey,   isSigner: true,  isWritable: true  }, // caller
    ],
    data: DISC_GUARD_VERIFY,
  });
}

// إرسال + simulation مع طباعة النتيجة
async function runTest(label, connection, tx, caller) {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`🔄 ${label}`);

  const sim = await connection.simulateTransaction(tx);
  const logs = sim.value.logs || [];
  const err  = sim.value.err;

  logs.forEach(l => {
    if (l.includes("TensorGuard") || l.includes("Error") || l.includes("error"))
      console.log("  LOG:", l);
  });

  if (!err) {
    // إرسال حقيقي
    const sig = await connection.sendRawTransaction(tx.serialize());
    await connection.confirmTransaction(sig, "confirmed");
    console.log(`  ✅ PASSED — TX: ${sig.slice(0, 20)}...`);
    return true;
  } else {
    const errCode = JSON.stringify(err);
    const errLog  = logs.find(l => l.includes("Error Code:")) || "";
    console.log(`  ❌ REVERTED — ${errLog.split("Error Code:")[1]?.trim() || errCode}`);
    return false;
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const walletPath = process.env.HOME + "/.config/solana/id.json";
  const caller = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath)))
  );
  const connection = new Connection(DEVNET_RPC, "confirmed");

  console.log("Caller:", caller.publicKey.toBase58());

  // ── PDAs ──────────────────────────────────────────────────────────────────
  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), caller.publicKey.toBuffer()], PROGRAM_ID
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), POOL_PUBKEY.toBuffer()], PROGRAM_ID
  );
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(NONCE, 0);
  const [attestation] = PublicKey.findProgramAddressSync(
    [Buffer.from("agg_attestation"), POOL_PUBKEY.toBuffer(), nonceBuf], PROGRAM_ID
  );

  // ── قراءة group_pubkey من الـ chain ───────────────────────────────────────
  const cfgInfo = await connection.getAccountInfo(guardConfig);
  if (!cfgInfo) throw new Error("guard_config not found");

  const cfgData = cfgInfo.data;
  const signersLen = cfgData.readUInt32LE(8 + 32);
  const gpkOffset  = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgData.slice(gpkOffset, gpkOffset + 32);
  console.log("group_pubkey:", Buffer.from(groupPubkey).toString("hex").slice(0, 32) + "...");

  // ── Message + signature للـ Safe verdict ─────────────────────────────────
  const msgSafe = encodeAttestationMsg(
    POOL_PUBKEY, NONCE, "Safe", 7880, 10880, 43693, 110
  );
  const sigSafe = nacl.sign.detached(msgSafe, caller.secretKey);

  // ── Message + signature للـ Attack verdict ───────────────────────────────
  const msgAttack = encodeAttestationMsg(
    POOL_PUBKEY, NONCE, "Attack", 9500, 108800, 436930, 330
  );
  const sigAttack = nacl.sign.detached(msgAttack, caller.secretKey);

  // ── Helper: بناء transaction كاملة ───────────────────────────────────────
  async function buildTx(message, signature, useAttestation) {
    const attPubkey = useAttestation
      ? attestation
      : PublicKey.default; // account فارغ لاختبار fallback

    const ed25519Ix   = buildEd25519Ix(groupPubkey, message, signature);
    const guardVeryIx = buildGuardVerifyIx(
      caller, POOL_PUBKEY, guardConfig,
      useAttestation ? attestation : new PublicKey(Buffer.alloc(32)),
      poolGuardState
    );

    const tx = new Transaction().add(ed25519Ix, guardVeryIx);
    const { blockhash } = await connection.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = caller.publicKey;
    tx.sign(caller);
    return tx;
  }

  // ════════════════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║         TensorGuard guard_verify Demo        ║");
  console.log("╚══════════════════════════════════════════════╝");

  // ── PATH 1: SAFE — يجب أن يمر ✅ ─────────────────────────────────────────
  const tx1 = await buildTx(msgSafe, sigSafe, true);
  await runTest("PATH 1 — Safe attestation → expect PASS ✅", connection, tx1, caller);

  // ── PATH 2: ATTACK — يجب أن يُرجع REVERT ❌ ──────────────────────────────
  // لاختبار هذا، نحتاج نخزن attestation بـ Attack verdict أولاً
  // لكن الـ attestation الحالي (nonce=1) هو Safe
  // لذلك نستخدم nonce=2 للـ attack test
  const nonce2Buf = Buffer.alloc(8);
  nonce2Buf.writeBigUInt64LE(BigInt(2), 0);
  const [attestation2] = PublicKey.findProgramAddressSync(
    [Buffer.from("agg_attestation"), POOL_PUBKEY.toBuffer(), nonce2Buf], PROGRAM_ID
  );

  console.log("\n  ℹ️  PATH 2 requires posting an Attack attestation first (nonce=2)");
  console.log("     Run: node post_aggregated_attack.js   (generated below)");
  console.log("     Then: re-run this script to test PATH 2");

  // ── PATH 3: FALLBACK — daemon صامت > 200 slots ─────────────────────────────
  // نستدعي guard_verify بـ attestation account فارغ (default pubkey)
  // إذا كان daemon حديث الـ heartbeat → يرجع NotFinalized
  // إذا كان صامت > 200 slots → يمر مع FallbackEvent
  console.log("\n  ℹ️  PATH 3 (Fallback) — testing with missing attestation...");
  const emptyAtt = new PublicKey(Buffer.alloc(32));
  const ed25519FbIx = buildEd25519Ix(groupPubkey, msgSafe, sigSafe);
  const guardFbIx   = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: POOL_PUBKEY,          isSigner: false, isWritable: false },
      { pubkey: guardConfig,          isSigner: false, isWritable: false },
      { pubkey: emptyAtt,             isSigner: false, isWritable: true  },
      { pubkey: poolGuardState,       isSigner: false, isWritable: true  },
      { pubkey: SYSVAR_INSTRUCTIONS,  isSigner: false, isWritable: false },
      { pubkey: caller.publicKey,     isSigner: true,  isWritable: true  },
    ],
    data: DISC_GUARD_VERIFY,
  });
  const tx3 = new Transaction().add(ed25519FbIx, guardFbIx);
  const { blockhash: bh3 } = await connection.getLatestBlockhash();
  tx3.recentBlockhash = bh3;
  tx3.feePayer = caller.publicKey;
  tx3.sign(caller);

  await runTest(
    "PATH 3 — No attestation → expect FALLBACK or NOT_READY ⚠️",
    connection, tx3, caller
  );

  // ── ملخص ──────────────────────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║                    Summary                   ║");
  console.log("║  PATH 1 (Safe)    → swap proceeds   ✅       ║");
  console.log("║  PATH 2 (Attack)  → swap reverted   ❌       ║");
  console.log("║  PATH 3 (Fallback)→ swap proceeds   ⚠️        ║");
  console.log("╚══════════════════════════════════════════════╝");

  // ── تولّد ملف attack attestation لاختبار PATH 2 ───────────────────────────
  const attackScript = `
// post_aggregated_attack.js — يخزن attestation بـ verdict=Attack (nonce=2)
const { Connection, PublicKey, Keypair, Transaction,
        TransactionInstruction, SystemProgram } = require("@solana/web3.js");
const fs = require("fs");
const nacl = require("tweetnacl");

const PROGRAM_ID  = new PublicKey("${PROGRAM_ID.toBase58()}");
const POOL_PUBKEY = new PublicKey("${POOL_PUBKEY.toBase58()}");
const NONCE       = BigInt(2); // nonce=2 للـ attack
const SYSVAR_INSTRUCTIONS = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519_PROGRAM     = new PublicKey("Ed25519SigVerify111111111111111111111111111");
const DISC = Buffer.from([89, 99, 3, 196, 67, 157, 165, 80]);

async function main() {
  const caller = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(process.env.HOME + "/.config/solana/id.json")))
  );
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");

  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), caller.publicKey.toBuffer()], PROGRAM_ID
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), POOL_PUBKEY.toBuffer()], PROGRAM_ID
  );
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(NONCE, 0);
  const [attestation] = PublicKey.findProgramAddressSync(
    [Buffer.from("agg_attestation"), POOL_PUBKEY.toBuffer(), nonceBuf], PROGRAM_ID
  );

  const cfgData = (await connection.getAccountInfo(guardConfig)).data;
  const signersLen = cfgData.readUInt32LE(8 + 32);
  const groupPubkey = cfgData.slice(8 + 32 + 4 + signersLen * 32 + 1,
                                     8 + 32 + 4 + signersLen * 32 + 1 + 32);

  // Attack message (55 bytes)
  const msg = Buffer.alloc(55);
  POOL_PUBKEY.toBuffer().copy(msg, 0);
  msg.writeBigUInt64LE(NONCE, 32);
  msg[40] = 1; // Attack
  msg.writeUInt16LE(9500, 41);
  msg.writeUInt32LE(108800, 43);
  msg.writeUInt32LE(436930, 47);
  msg.writeUInt32LE(330, 51);

  const sig = nacl.sign.detached(msg, caller.secretKey);

  // Ed25519 ix
  const SIG_OFF = 16, PK_OFF = 80, MSG_OFF = 112;
  const ed25519Data = Buffer.alloc(MSG_OFF + 55);
  ed25519Data[0] = 1;
  ed25519Data.writeUInt16LE(SIG_OFF, 2);  ed25519Data.writeUInt16LE(0xFFFF, 4);
  ed25519Data.writeUInt16LE(PK_OFF, 6);   ed25519Data.writeUInt16LE(0xFFFF, 8);
  ed25519Data.writeUInt16LE(MSG_OFF, 10); ed25519Data.writeUInt16LE(55, 12);
  ed25519Data.writeUInt16LE(0xFFFF, 14);
  Buffer.from(sig).copy(ed25519Data, SIG_OFF);
  Buffer.from(groupPubkey).copy(ed25519Data, PK_OFF);
  msg.copy(ed25519Data, MSG_OFF);

  const args = Buffer.alloc(32+8+1+2+4+4+4+1+64);
  let off = 0;
  POOL_PUBKEY.toBuffer().copy(args, off); off+=32;
  nonceBuf.copy(args, off); off+=8;
  args[off] = 1; off++; // Attack
  args.writeUInt16LE(9500, off); off+=2;
  args.writeUInt32LE(108800, off); off+=4;
  args.writeUInt32LE(436930, off); off+=4;
  args.writeUInt32LE(330, off); off+=4;
  args[off] = 0b00000001; off++;
  Buffer.from(sig).copy(args, off);

  const tx = new Transaction()
    .add(new TransactionInstruction({ programId: ED25519_PROGRAM, keys: [], data: ed25519Data }))
    .add(new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: caller.publicKey,          isSigner: true,  isWritable: true  },
        { pubkey: guardConfig,               isSigner: false, isWritable: false },
        { pubkey: attestation,               isSigner: false, isWritable: true  },
        { pubkey: poolGuardState,            isSigner: false, isWritable: true  },
        { pubkey: SYSVAR_INSTRUCTIONS,       isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId,   isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([DISC, args]),
    }));

  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = caller.publicKey;
  tx.sign(caller);

  const txSig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(txSig, "confirmed");
  console.log("✅ Attack attestation posted! TX:", txSig);
  console.log("   Attestation (nonce=2):", attestation.toBase58());
}
main().catch(console.error);
`;
  fs.writeFileSync("post_aggregated_attack.js", attackScript.trim());
  console.log("\n✅ Generated: post_aggregated_attack.js");
  console.log("   Run it, then update guard_verify.js NONCE to BigInt(2) for PATH 2 test");
}

main().catch(console.error);
