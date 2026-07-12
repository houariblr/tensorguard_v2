/**
 * post_aggregated_v3.js
 *
 * الإصلاح الكامل: يبني transaction بـ instructionين:
 *   ix[0]: Ed25519Program — يتحقق من الـ FROST signature
 *   ix[1]: post_aggregated — يتحقق أن ix[0] شغل فعلاً
 *
 * الـ accounts الصحيحة (من post_aggregated.rs):
 *   coordinator     (mut, signer)
 *   guard_config    (read, PDA)
 *   attestation     (mut, init, PDA)
 *   pool_guard_state(mut, PDA)
 *   instructions_sysvar
 *   system_program
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
  Ed25519Program,                // ← للـ precompile instruction
} = require("@solana/web3.js");
const fs   = require("fs");
const nacl = require("tweetnacl"); // npm install tweetnacl

// ─── Config ─────────────────────────────────────────────────────────────────
const DEVNET_RPC  = "https://api.devnet.solana.com";
const PROGRAM_ID  = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const POOL_PUBKEY = new PublicKey("FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg");
const NONCE       = BigInt(1);

// Sysvar pubkeys
const SYSVAR_INSTRUCTIONS = new PublicKey("Sysvar1nstructions1111111111111111111111111");

// ─── Discriminator for post_aggregated ──────────────────────────────────────
// anchor build يولد هذا من sha256("global:post_aggregated")[0..8]
const DISC = Buffer.from([89, 99, 3, 196, 67, 157, 165, 80]);

// ─── Encode the canonical 55-byte attestation message ───────────────────────
// يجب أن يطابق encode_attestation_msg() في post_aggregated.rs تماماً:
//   pool[32] | nonce[8] | verdict[1] | confidence_bps[2] |
//   lyapunov_x100[4] | kolmogorov_x100[4] | ricci_x100[4]
function encodeAttestationMsg(pool, nonce, verdict, confidenceBps,
                               lyapunovX100, kolmogorovX100, ricciX100) {
  const msg = Buffer.alloc(55);
  let off = 0;
  pool.toBuffer().copy(msg, off);                 off += 32; // pool pubkey
  msg.writeBigUInt64LE(nonce, off);               off += 8;  // nonce
  msg[off] = verdict === "Attack" ? 1 : 0;        off += 1;  // verdict
  msg.writeUInt16LE(confidenceBps, off);          off += 2;  // confidence_bps
  msg.writeUInt32LE(lyapunovX100, off);           off += 4;  // lyapunov_x100
  msg.writeUInt32LE(kolmogorovX100, off);         off += 4;  // kolmogorov_x100
  msg.writeUInt32LE(ricciX100, off);                         // ricci_x100
  return msg;
}

// ─── Build the Ed25519Program precompile instruction ────────────────────────
// Solana Ed25519 instruction data layout (per SVM spec):
//   [0]     num_signatures: u8
//   [1]     padding: u8  (= 0)
//   [2..4]  signature_offset: u16
//   [4..6]  signature_ix_index: u16 (0xFFFF = current ix)
//   [6..8]  pubkey_offset: u16
//   [8..10] pubkey_ix_index: u16
//   [10..12] message_offset: u16
//   [12..14] message_size: u16
//   [14..16] message_ix_index: u16
//   [16..]  signature(64) | pubkey(32) | message(55)
function buildEd25519Instruction(pubkey, message, signature) {
  const SIG_OFFSET = 16;
  const PK_OFFSET  = SIG_OFFSET + 64;
  const MSG_OFFSET = PK_OFFSET  + 32;

  const data = Buffer.alloc(16 + 64 + 32 + message.length);

  data[0] = 1;     // num_signatures
  data[1] = 0;     // padding

  data.writeUInt16LE(SIG_OFFSET, 2);    // signature_offset
  data.writeUInt16LE(0xFFFF, 4);         // signature_ix_index (current)
  data.writeUInt16LE(PK_OFFSET, 6);     // pubkey_offset
  data.writeUInt16LE(0xFFFF, 8);         // pubkey_ix_index
  data.writeUInt16LE(MSG_OFFSET, 10);   // message_offset
  data.writeUInt16LE(message.length, 12); // message_size
  data.writeUInt16LE(0xFFFF, 14);        // message_ix_index

  Buffer.from(signature).copy(data, SIG_OFFSET);
  Buffer.from(pubkey).copy(data,    PK_OFFSET);
  Buffer.from(message).copy(data,   MSG_OFFSET);

  return new TransactionInstruction({
    programId: new PublicKey("Ed25519SigVerify111111111111111111111111111"),
    keys: [],   // Ed25519Program precompile لا يحتاج accounts
    data,
  });
}

// ─── Main ────────────────────────────────────────────────────────────────────
async function main() {
  // --- Load coordinator keypair (must be in guard_config.signers) ---
  const walletPath = process.env.HOME + "/.config/solana/id.json";
  const coordinator = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath)))
  );

  console.log("Coordinator:", coordinator.publicKey.toBase58());

  const connection = new Connection(DEVNET_RPC, "confirmed");

  // --- PDAs ---
  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), coordinator.publicKey.toBuffer()],
    PROGRAM_ID
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), POOL_PUBKEY.toBuffer()],
    PROGRAM_ID
  );
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(NONCE, 0);
  const [attestation] = PublicKey.findProgramAddressSync(
    [Buffer.from("agg_attestation"), POOL_PUBKEY.toBuffer(), nonceBuf],
    PROGRAM_ID
  );

  console.log("guardConfig:    ", guardConfig.toBase58());
  console.log("poolGuardState: ", poolGuardState.toBase58());
  console.log("attestation:    ", attestation.toBase58());

  // --- الـ guard_config على الـ chain لاسترجاع group_pubkey ---
  // group_pubkey يُستخدم للـ Ed25519 verification
  // نقرأه من الـ account data
  console.log("\nReading guard_config from chain...");
  const cfgAccountInfo = await connection.getAccountInfo(guardConfig);
  if (!cfgAccountInfo) {
    throw new Error("guard_config account not found! هل شغّلت initialize()؟");
  }

  // GuardConfig layout (من state.rs):
  // discriminator[8] | authority[32] | signers_len[4] | signers[N*32] |
  // threshold[1] | group_pubkey[32] | active[1] | bump[1]
  const cfgData = cfgAccountInfo.data;
  const signersLen = cfgData.readUInt32LE(8 + 32); // بعد discriminator + authority
  const groupPubkeyOffset = 8 + 32 + 4 + signersLen * 32 + 1;
  const groupPubkey = cfgData.slice(groupPubkeyOffset, groupPubkeyOffset + 32);

  console.log("group_pubkey (from chain):", Buffer.from(groupPubkey).toString("hex"));

  // --- تحقق أن group_pubkey ليس صفراً ---
  // إذا كان صفراً (default) فنستخدم coordinator keypair مباشرة للاختبار
  const isGroupPubkeyEmpty = groupPubkey.every(b => b === 0);
  if (isGroupPubkeyEmpty) {
    console.warn("\n⚠️  group_pubkey is all zeros!");
    console.warn("   هذا يعني أن initialize() استُدعي بـ group_pubkey=[0;32]");
    console.warn("   للـ demo: سنستخدم coordinator keypair كـ group key مؤقتاً\n");
  }

  // --- بناء الـ attestation message (55 bytes) ---
  const verdict        = "Safe";
  const confidenceBps  = 7880;
  const lyapunovX100   = 10880;
  const kolmogorovX100 = 43693;
  const ricciX100      = 110;
  const signerBitmask  = 0b00000001;

  const message = encodeAttestationMsg(
    POOL_PUBKEY, NONCE, verdict,
    confidenceBps, lyapunovX100, kolmogorovX100, ricciX100
  );
  console.log("Attestation message (55 bytes):", message.toString("hex"));

  // --- توقيع الـ message ---
  // للـ demo: نوقع بـ coordinator keypair
  // في production: group_pubkey هو FROST aggregated public key
  const signingKeypair = isGroupPubkeyEmpty ? coordinator : coordinator;
  const signatureBytes = nacl.sign.detached(message, signingKeypair.secretKey);
  const actualPubkey   = isGroupPubkeyEmpty
    ? coordinator.publicKey.toBytes()
    : groupPubkey;

  console.log("Signing pubkey:", Buffer.from(actualPubkey).toString("hex").slice(0, 16) + "...");

  // --- بناء الـ AggregatedArgs (الـ instruction data) ---
  const args = Buffer.alloc(32 + 8 + 1 + 2 + 4 + 4 + 4 + 1 + 64);
  let off = 0;
  POOL_PUBKEY.toBuffer().copy(args, off);      off += 32;
  nonceBuf.copy(args, off);                    off += 8;
  args[off] = verdict === "Attack" ? 1 : 0;   off += 1;
  args.writeUInt16LE(confidenceBps, off);      off += 2;
  args.writeUInt32LE(lyapunovX100, off);       off += 4;
  args.writeUInt32LE(kolmogorovX100, off);     off += 4;
  args.writeUInt32LE(ricciX100, off);          off += 4;
  args[off] = signerBitmask;                   off += 1;
  Buffer.from(signatureBytes).copy(args, off);             // agg_signature[64]

  const ixData = Buffer.concat([DISC, args]);

  // --- ix[0]: Ed25519 precompile ---
  const ed25519Ix = buildEd25519Instruction(actualPubkey, message, signatureBytes);

  // --- ix[1]: post_aggregated ---
  // accounts الترتيب الصحيح حسب PostAggregated struct:
  //   coordinator, guard_config, attestation, pool_guard_state,
  //   instructions_sysvar, system_program
  const postAggIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: coordinator.publicKey, isSigner: true,  isWritable: true  }, // coordinator
      { pubkey: guardConfig,           isSigner: false, isWritable: false }, // guard_config
      { pubkey: attestation,           isSigner: false, isWritable: true  }, // attestation
      { pubkey: poolGuardState,        isSigner: false, isWritable: true  }, // pool_guard_state
      { pubkey: SYSVAR_INSTRUCTIONS,   isSigner: false, isWritable: false }, // instructions_sysvar
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
    ],
    data: ixData,
  });

  // --- Build & send transaction ---
  const tx = new Transaction().add(ed25519Ix, postAggIx);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = coordinator.publicKey;
  tx.sign(coordinator);

  // --- Simulate first ---
  console.log("\nSimulating transaction...");
  const sim = await connection.simulateTransaction(tx);
  const simErr = sim.value.err;
  const simLogs = sim.value.logs || [];

  simLogs.forEach(l => console.log(" ", l));

  if (simErr) {
    console.error("\n❌ Simulation failed:", JSON.stringify(simErr));

    // تحليل الخطأ
    const errLog = simLogs.find(l => l.includes("Error"));
    if (errLog?.includes("WrongSigner")) {
      console.error("\n💡 WrongSigner — تحقق أن group_pubkey في initialize() == signing pubkey");
      console.error("   إذا كان group_pubkey=[0;32]، أعد تشغيل initialize() مع pubkey صحيح");
    }
    if (errLog?.includes("UntrustedSigner")) {
      console.error("\n💡 UntrustedSigner — coordinator.publicKey يجب أن يكون في guard_config.signers");
      console.error("   Coordinator:", coordinator.publicKey.toBase58());
    }
    if (errLog?.includes("BelowThreshold")) {
      console.error("\n💡 BelowThreshold — signer_bitmask.count_ones() < threshold");
      console.error("   bitmask:", signerBitmask.toString(2), "count:", signerBitmask.toString(2).split("1").length - 1);
    }
    return;
  }

  // --- Send ---
  console.log("\n✅ Simulation passed! Sending...");
  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, "confirmed");

  console.log("\n✅ post_aggregated confirmed!");
  console.log("   TX:          ", sig);
  console.log("   Attestation: ", attestation.toBase58());
  console.log("   Nonce:       ", NONCE.toString());
  console.log("   Verdict:     ", verdict);
}

main().catch(err => {
  console.error("Fatal:", err.message || err);
  if (err.logs) err.logs.forEach(l => console.error(" ", l));
});