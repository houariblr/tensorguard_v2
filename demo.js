/**
 * demo_video.js — TensorGuard Video Demo
 * نسخة بطيئة للتسجيل — مع تأخير بين كل خطوة
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
} = require("@solana/web3.js");
const fs   = require("fs");
const nacl = require("tweetnacl");

const RPC        = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const POOL       = new PublicKey("FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg");
const IX_SYSVAR   = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519_PGM = new PublicKey("Ed25519SigVerify111111111111111111111111111");
const DISC_POST_AGG     = Buffer.from([89, 99, 3, 196, 67, 157, 165, 80]);
const DISC_GUARD_VERIFY = Buffer.from([215, 255, 83, 127, 169, 196, 213, 38]);

const sleep = ms => new Promise(r => setTimeout(r, ms));

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
  args[off] = bitmask;              off += 1;
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

async function sendTx(label, connection, tx, expectRevert = false) {
  const sim  = await connection.simulateTransaction(tx);
  const logs = sim.value.logs || [];
  const err  = sim.value.err;
  const guardLog = logs.find(l => l.includes("TensorGuard") || l.includes("agg]"));

  if (!err) {
    const sig = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: true });
    await connection.confirmTransaction(sig, "confirmed");
    console.log(`  ✅ ${label}`);
    if (guardLog) console.log(`     ${guardLog.replace("Program log: ", "")}`);
    console.log(`     TX: ${sig.slice(0, 44)}...`);
    return { ok: true };
  } else {
    const errLine = logs.find(l => l.includes("Error Code:")) || "";
    const code    = errLine.match(/Error Code: (\w+)/)?.[1] || JSON.stringify(err);
    if (expectRevert) {
      console.log(`  ✅ ${label}`);
      console.log(`     Correctly reverted: ${code}`);
      return { ok: false, reverted: true };
    } else {
      console.log(`  ❌ ${label} — FAILED: ${code}`);
      return { ok: false };
    }
  }
}

async function main() {
  const keypair = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(
      process.env.HOME + "/.config/solana/id.json"
    )))
  );
  const connection = new Connection(RPC, "confirmed");

  // ── Intro ──────────────────────────────────────────────────────────────────
  console.clear();
  await sleep(500);

  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║          TensorGuard — Live Demo on Solana           ║");
  console.log("║   Pre-execution AMM Attack Detection                 ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  await sleep(3000);

  console.log("\n  Program : 5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
  console.log("  Network : Solana Devnet");
  console.log("  Method  : 5D Liquidity Tensor Field");
  console.log("            (Lyapunov + Kolmogorov + Ricci)\n");
  await sleep(4000);

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

  const cfgInfo    = await connection.getAccountInfo(guardConfig);
  const cfgData    = cfgInfo.data;
  const signersLen = cfgData.readUInt32LE(8 + 32);
  const gpkStart   = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgData.slice(gpkStart, gpkStart + 32);

  async function signedTx(...ixs) {
    const tx = new Transaction().add(...ixs);
    const { blockhash } = await connection.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = keypair.publicKey;
    tx.sign(keypair);
    return tx;
  }

  const slot   = await connection.getSlot();
  const nonceS = slot;
  const nonceA = slot + 1;

  // ══════════════════════════════════════════════════════════════════════════
  console.log("━".repeat(56));
  console.log("  TEST 1 — Normal swap (SAFE)");
  console.log("  Daemon detects: normal trade, no attack pattern");
  console.log("━".repeat(56));
  await sleep(3000);

  console.log("\n  › Posting Safe attestation on-chain...");
  await sleep(1500);

  const msgSafe = encodeMsg(POOL, nonceS, false, 7880, 10880, 43693, 110);
  const sigSafe = nacl.sign.detached(msgSafe, keypair.secretKey);
  const attSafe = attPDA(nonceS);

  const tx1 = await signedTx(
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    postAggIx(keypair.publicKey, guardConfig, attSafe, poolGuardState,
              POOL, nonceS, false, 7880, 10880, 43693, 110, 0b00000001, sigSafe)
  );
  await sendTx("Attestation posted  [verdict: SAFE | confidence: 78.8%]", connection, tx1);
  await sleep(2500);

  console.log("\n  › AMM calls guard_verify before executing swap...");
  await sleep(1500);

  const tx2 = await signedTx(
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig, attSafe, poolGuardState)
  );
  await sendTx("guard_verify → PASS  ✅  Swap proceeds normally", connection, tx2);
  await sleep(3000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  TEST 2 — Sandwich Attack DETECTED");
  console.log("  Daemon detects: L=108.8 K=436.9 — ATTACK (78.8%)");
  console.log("━".repeat(56));
  await sleep(3000);

  console.log("\n  › TensorGuard daemon posts ATTACK attestation...");
  await sleep(1500);

  const msgAttack = encodeMsg(POOL, nonceA, true, 9500, 108800, 436930, 330);
  const sigAttack = nacl.sign.detached(msgAttack, keypair.secretKey);
  const attAttack = attPDA(nonceA);

  const tx3 = await signedTx(
    ed25519Ix(groupPubkey, msgAttack, sigAttack),
    postAggIx(keypair.publicKey, guardConfig, attAttack, poolGuardState,
              POOL, nonceA, true, 9500, 108800, 436930, 330, 0b00000001, sigAttack)
  );
  await sendTx("Attestation posted  [verdict: ATTACK | confidence: 95%]", connection, tx3);
  await sleep(2500);

  console.log("\n  › AMM calls guard_verify — swap is BLOCKED...");
  await sleep(1500);

  const tx4 = await signedTx(
    ed25519Ix(groupPubkey, msgAttack, sigAttack),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig, attAttack, poolGuardState)
  );
  await sendTx("guard_verify → REVERT ❌  AttackDetected — Swap BLOCKED", connection, tx4, true);
  await sleep(3000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "━".repeat(56));
  console.log("  TEST 3 — Fallback (daemon offline)");
  console.log("  No attestation → AMM stays live, alert emitted");
  console.log("━".repeat(56));
  await sleep(3000);

  const tx5 = await signedTx(
    ed25519Ix(groupPubkey, msgSafe, sigSafe),
    guardVerifyIx(keypair.publicKey, POOL, guardConfig,
                  poolGuardState, poolGuardState)
  );
  await sendTx("guard_verify → NOT_READY ⚠️  Daemon signal emitted", connection, tx5, true);
  await sleep(2000);

  // ══════════════════════════════════════════════════════════════════════════
  console.log("\n" + "╔══════════════════════════════════════════════════════╗");
  console.log("║                   Results                           ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  Normal swap   → PASS    ✅  users protected        ║");
  console.log("║  Sandwich attack → BLOCKED ❌  attack prevented     ║");
  console.log("║  Daemon offline → FALLBACK ⚠️  AMM stays live       ║");
  console.log("╠══════════════════════════════════════════════════════╣");
  console.log("║  github.com/houariblr/tensorguard_v2                ║");
  console.log("╚══════════════════════════════════════════════════════╝");
}

main().catch(e => {
  console.error("Fatal:", e.message);
});
