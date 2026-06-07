const { Connection, PublicKey, Keypair, Transaction, TransactionInstruction, SystemProgram } = require("@solana/web3.js");
const fs = require("fs");

// Manual borsh encoding
function encodeInitialize(signers, threshold) {
  // discriminator (8 bytes)
  const disc = Buffer.from([175, 175, 109, 31, 13, 152, 155, 237]);
  
  // Vec<Pubkey>: u32 length + pubkeys
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(signers.length, 0);
  const signerBufs = signers.map(s => s.toBuffer());
  
  // threshold: u8
  const threshBuf = Buffer.from([threshold]);
  
  // group_pubkey: [u8; 32] — same as first signer for now
  const groupPubkey = signers[0].toBuffer();

  return Buffer.concat([disc, lenBuf, ...signerBufs, threshBuf, groupPubkey]);
}

async function main() {
  const walletPath = process.env.HOME + "/.config/solana/id.json";
  const payer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath)))
  );

  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  const programId = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");

  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), payer.publicKey.toBuffer()],
    programId
  );

  console.log("Authority:   ", payer.publicKey.toBase58());
  console.log("GuardConfig: ", guardConfig.toBase58());

  const data = encodeInitialize([payer.publicKey], 1);

  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: guardConfig,              isSigner: false, isWritable: true },
      { pubkey: payer.publicKey,          isSigner: true,  isWritable: true },
      { pubkey: SystemProgram.programId,  isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(ix);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);

  const sig = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    preflightCommitment: "confirmed"
  });
  await connection.confirmTransaction(sig, "confirmed");

  console.log("\n✅ Initialized!");
  console.log("TX:", sig);
  console.log("Explorer: https://explorer.solana.com/tx/" + sig + "?cluster=devnet");
}

main().catch(console.error);
