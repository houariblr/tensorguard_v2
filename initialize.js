/**
 * initialize.js — TensorGuard Initialize
 * ينشئ GuardConfig account على السلسلة
 * يُشغل مرة واحدة فقط
 */

const {
  Connection, PublicKey, Keypair, Transaction,
  TransactionInstruction, SystemProgram,
} = require("@solana/web3.js");
const fs = require("fs");

// ─── Config ──────────────────────────────────────────────────────────────────
const RPC        = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");

// Discriminator: sha256("global:initialize")[0..8]
// من tests.js: [175, 175, 109, 31, 13, 152, 155, 237]
const DISC_INIT = Buffer.from([175, 175, 109, 31, 13, 152, 155, 237]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * تسلسل Borsh لـ Vec<Pubkey>:
 *   4 bytes (u32 LE) = الطول
 *   N × 32 bytes = المفاتيح
 */
function serializeSigners(pubkeys) {
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(pubkeys.length, 0);
  return Buffer.concat([lenBuf, ...pubkeys.map(pk => pk.toBuffer())]);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const authority = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(
      process.env.HOME + "/.config/solana/id.json"
    )))
  );
  const connection = new Connection(RPC, "confirmed");

  console.log("Authority:", authority.publicKey.toBase58());

  // ── PDA ───────────────────────────────────────────────────────────────────
  const [guardConfig, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), authority.publicKey.toBuffer()],
    PROGRAM_ID
  );
  console.log("GuardConfig PDA:", guardConfig.toBase58());
  console.log("Bump:", bump);

  // ── التحقق من عدم الوجود مسبقاً ───────────────────────────────────────────
  const existing = await connection.getAccountInfo(guardConfig);
  if (existing) {
    console.log("⚠️  GuardConfig already exists! Skipping initialization.");
    console.log("   Run 'npm run demo' or 'node guard_verify.js' instead.");
    return;
  }

  // ── بناء Instruction Data ────────────────────────────────────────────────
  // Anchor format:
  //   [discriminator 8] + [signers Vec] + [threshold u8] + [group_pubkey 32]

  const initialSigners = [authority.publicKey]; // للـ demo: signer واحد
  const threshold    = 1;                       // يكفي signer واحد
  const groupPubkey  = authority.publicKey.toBuffer(); // للـ demo: نفس المفتاح

  const ixData = Buffer.concat([
    DISC_INIT,
    serializeSigners(initialSigners),
    Buffer.from([threshold]),
    groupPubkey,
  ]);

  console.log("\nInstruction data length:", ixData.length, "bytes");
  console.log("Signers:", initialSigners.map(s => s.toBase58()));
  console.log("Threshold:", threshold);
  console.log("Group pubkey:", groupPubkey.toString("hex").slice(0, 16) + "...");

  // ── Accounts (من Rust: Initialize<'info>) ───────────────────────────────
  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: guardConfig,     isSigner: false, isWritable: true  }, // init
      { pubkey: authority.publicKey, isSigner: true,  isWritable: true  }, // payer
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: ixData,
  });

  // ── Send ──────────────────────────────────────────────────────────────────
  const tx = new Transaction().add(ix);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = authority.publicKey;
  tx.sign(authority);

  console.log("\n📡 Sending initialize transaction...");

  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, "confirmed");

  console.log("\n✅ TensorGuard initialized successfully!");
  console.log("   GuardConfig:", guardConfig.toBase58());
  console.log("   TX:        ", sig);
  console.log("\nNext steps:");
  console.log("   node heartbeat.js");
  console.log("   node post_aggregated.js");
  console.log("   node guard_verify.js");
}

main().catch(err => {
  console.error("❌ Fatal:", err.message);
  process.exit(1);
});