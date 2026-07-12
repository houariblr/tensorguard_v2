/**
 * post_aggregated_v4.js — TensorGuard Post Aggregated (Fixed Nonce)
 * يستخدم nonce فريد تلقائياً (current slot) لتجنب "already in use"
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
} = require("@solana/web3.js");
const fs   = require("fs");
const nacl = require("tweetnacl");

const DEVNET_RPC  = "https://api.devnet.solana.com";
const PROGRAM_ID  = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const POOL_PUBKEY = new PublicKey("FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg");
const SYSVAR_INSTRUCTIONS = new PublicKey("Sysvar1nstructions1111111111111111111111111");
const ED25519_PROGRAM = new PublicKey("Ed25519SigVerify111111111111111111111111111");

const DISC = Buffer.from([89, 99, 3, 196, 67, 157, 165, 80]);

function encodeAttestationMsg(pool, nonce, verdict, confidenceBps,
                               lyapunovX100, kolmogorovX100, ricciX100) {
  const msg = Buffer.alloc(55);
  let off = 0;
  pool.toBuffer().copy(msg, off);                 off += 32;
  msg.writeBigUInt64LE(nonce, off);               off += 8;
  msg[off] = verdict === "Attack" ? 1 : 0;        off += 1;
  msg.writeUInt16LE(confidenceBps, off);          off += 2;
  msg.writeUInt32LE(lyapunovX100, off);           off += 4;
  msg.writeUInt32LE(kolmogorovX100, off);        off += 4;
  msg.writeUInt32LE(ricciX100, off);
  return msg;
}

function buildEd25519Instruction(pubkey, message, signature) {
  const SIG_OFFSET = 16, PK_OFFSET = 80, MSG_OFFSET = 112;
  const data = Buffer.alloc(MSG_OFFSET + message.length);
  data[0] = 1; data[1] = 0;
  data.writeUInt16LE(SIG_OFFSET, 2);   data.writeUInt16LE(0xFFFF, 4);
  data.writeUInt16LE(PK_OFFSET, 6);    data.writeUInt16LE(0xFFFF, 8);
  data.writeUInt16LE(MSG_OFFSET, 10);  data.writeUInt16LE(message.length, 12);
  data.writeUInt16LE(0xFFFF, 14);
  Buffer.from(signature).copy(data, SIG_OFFSET);
  Buffer.from(pubkey).copy(data, PK_OFFSET);
  Buffer.from(message).copy(data, MSG_OFFSET);
  return new TransactionInstruction({ programId: ED25519_PROGRAM, keys: [], data });
}

async function main() {
  const coordinator = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(
      process.env.HOME + "/.config/solana/id.json"
    )))
  );
  const connection = new Connection(DEVNET_RPC, "confirmed");

  // ── nonce فريد: current slot ───────────────────────────────────────────
  const slot  = await connection.getSlot();
  const NONCE = BigInt(slot);  // ← فريد كل مرة!
  console.log("Current slot:", slot, "| Nonce:", NONCE.toString());

  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), coordinator.publicKey.toBuffer()], PROGRAM_ID
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), POOL_PUBKEY.toBuffer()], PROGRAM_ID
  );
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(NONCE, 0);
  const [attestation] = PublicKey.findProgramAddressSync(
    [Buffer.from("agg_attestation"), POOL_PUBKEY.toBuffer(), nonceBuf], PROGRAM_ID
  );

  console.log("Attestation PDA:", attestation.toBase58());

  // ── التحقق من عدم الوجود مسبقاً ────────────────────────────────────────
  const existing = await connection.getAccountInfo(attestation);
  if (existing) {
    console.log("⚠️  Attestation already exists! Using slot+1...");
    nonceBuf.writeBigUInt64LE(NONCE + BigInt(1), 0);
    const [attestation2] = PublicKey.findProgramAddressSync(
      [Buffer.from("agg_attestation"), POOL_PUBKEY.toBuffer(), nonceBuf], PROGRAM_ID
    );
    console.log("New Attestation PDA:", attestation2.toBase58());
    // استخدم attestation2 في ما بعد
  }

  // ── قراءة group_pubkey ─────────────────────────────────────────────────
  const cfgInfo = await connection.getAccountInfo(guardConfig);
  if (!cfgInfo) throw new Error("guard_config not found — run initialize first");
  const cfgData = cfgInfo.data;
  const signersLen = cfgData.readUInt32LE(8 + 32);
  const gpkStart = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgData.slice(gpkStart, gpkStart + 32);

  // ── بناء Message + Signature ───────────────────────────────────────────
  const verdict = "Safe", confidenceBps = 7880;
  const lyapunovX100 = 10880, kolmogorovX100 = 43693, ricciX100 = 110;
  const signerBitmask = 0b00000001;

  const message = encodeAttestationMsg(POOL_PUBKEY, NONCE, verdict,
    confidenceBps, lyapunovX100, kolmogorovX100, ricciX100);

  const signatureBytes = nacl.sign.detached(message, coordinator.secretKey);
  const actualPubkey = groupPubkey.every(b => b === 0)
    ? coordinator.publicKey.toBytes()
    : groupPubkey;

  // ── بناء Instruction Data ───────────────────────────────────────────────
  const args = Buffer.alloc(32 + 8 + 1 + 2 + 4 + 4 + 4 + 1 + 64);
  let off = 0;
  POOL_PUBKEY.toBuffer().copy(args, off);    off += 32;
  nonceBuf.copy(args, off);                 off += 8;
  args[off] = 0;                             off += 1;  // Safe
  args.writeUInt16LE(confidenceBps, off);    off += 2;
  args.writeUInt32LE(lyapunovX100, off);     off += 4;
  args.writeUInt32LE(kolmogorovX100, off);   off += 4;
  args.writeUInt32LE(ricciX100, off);        off += 4;
  args[off] = signerBitmask;               off += 1;
  Buffer.from(signatureBytes).copy(args, off);

  const ed25519Ix = buildEd25519Instruction(actualPubkey, message, signatureBytes);

  const postAggIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: coordinator.publicKey, isSigner: true,  isWritable: true  },
      { pubkey: guardConfig,           isSigner: false, isWritable: false },
      { pubkey: attestation,           isSigner: false, isWritable: true  },
      { pubkey: poolGuardState,        isSigner: false, isWritable: true  },
      { pubkey: SYSVAR_INSTRUCTIONS,   isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([DISC, args]),
  });

  const tx = new Transaction().add(ed25519Ix, postAggIx);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = coordinator.publicKey;
  tx.sign(coordinator);

  console.log("\n📡 Simulating...");
  const sim = await connection.simulateTransaction(tx);
  if (sim.value.err) {
    console.error("❌ Simulation failed:", JSON.stringify(sim.value.err));
    (sim.value.logs || []).forEach(l => console.log(" ", l));
    return;
  }

  console.log("✅ Simulation passed! Sending...");
  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, "confirmed");

  console.log("\n✅ post_aggregated confirmed!");
  console.log("   TX:         ", sig);
  console.log("   Attestation:", attestation.toBase58());
  console.log("   Nonce:      ", NONCE.toString());
  console.log("\nNext: node guard_verify.js (use nonce =", NONCE.toString(), ")");
}

main().catch(err => {
  console.error("Fatal:", err.message);
  process.exit(1);
});