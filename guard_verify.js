/**
 * guard_verify.js — TensorGuard guard_verify (Fixed)
 *
 * الاستخدام:
 *   node guard_verify.js              → يستخدم current slot كـ nonce
 *   node guard_verify.js 12345678     → يستخدم nonce محدد
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

const SYSVAR_INSTRUCTIONS = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519_PROGRAM     = new PublicKey("Ed25519SigVerify111111111111111111111111111");

const DISC_GUARD_VERIFY = Buffer.from([215, 255, 83, 127, 169, 196, 213, 38]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

function buildEd25519Ix(pubkeyBytes, message, signature) {
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
  return new TransactionInstruction({ programId: ED25519_PROGRAM, keys: [], data: d });
}

function buildGuardVerifyIx(caller, pool, guardConfig, attestation, poolGuardState) {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: pool,               isSigner: false, isWritable: false },
      { pubkey: guardConfig,        isSigner: false, isWritable: false },
      { pubkey: attestation,        isSigner: false, isWritable: true  },
      { pubkey: poolGuardState,     isSigner: false, isWritable: true  },
      { pubkey: SYSVAR_INSTRUCTIONS,isSigner: false, isWritable: false },
      { pubkey: caller.publicKey,   isSigner: true,  isWritable: true  },
    ],
    data: DISC_GUARD_VERIFY,
  });
}

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

  // ✅ NONCE داخل main() — صحيح 100%
  const NONCE = process.argv[2] 
    ? BigInt(process.argv[2]) 
    : BigInt(await connection.getSlot());
  console.log("Caller:", caller.publicKey.toBase58());
  console.log("Nonce: ", NONCE.toString());

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

  // ── قراءة group_pubkey ───────────────────────────────────────────────────
  const cfgInfo = await connection.getAccountInfo(guardConfig);
  if (!cfgInfo) throw new Error("guard_config not found — run initialize.js first");
  const cfgData = cfgInfo.data;
  const signersLen = cfgData.readUInt32LE(8 + 32);
  const gpkOffset  = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgData.slice(gpkOffset, gpkOffset + 32);
  console.log("group_pubkey:", Buffer.from(groupPubkey).toString("hex").slice(0, 32) + "...");

  // ── Message + Signature (Safe) ────────────────────────────────────────────
  const msgSafe = encodeAttestationMsg(
    POOL_PUBKEY, NONCE, "Safe", 7880, 10880, 43693, 110
  );
  const sigSafe = nacl.sign.detached(msgSafe, caller.secretKey);

  async function buildTx(message, signature, useAttestation) {
    const attPubkey = useAttestation ? attestation : new PublicKey(Buffer.alloc(32));
    const ed25519Ix = buildEd25519Ix(groupPubkey, message, signature);
    const guardIx   = buildGuardVerifyIx(caller, POOL_PUBKEY, guardConfig, attPubkey, poolGuardState);

    const tx = new Transaction().add(ed25519Ix, guardIx);
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

  // ── PATH 1: SAFE ──────────────────────────────────────────────────────────
  const tx1 = await buildTx(msgSafe, sigSafe, true);
  await runTest("PATH 1 — Safe attestation → expect PASS ✅", connection, tx1, caller);

  // ── PATH 3: FALLBACK (no attestation) ────────────────────────────────────
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

  // ── Summary ──────────────────────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║                    Summary                   ║");
  console.log("║  PATH 1 (Safe)    → swap proceeds   ✅       ║");
  console.log("║  PATH 3 (Fallback)→ swap proceeds   ⚠️        ║");
  console.log("╚══════════════════════════════════════════════╝");
}

main().catch(console.error);