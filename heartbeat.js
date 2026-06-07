const { Connection, PublicKey, Keypair, Transaction, TransactionInstruction, SystemProgram } = require("@solana/web3.js");
const fs = require("fs");

async function main() {
  const walletPath = process.env.HOME + "/.config/solana/id.json";
  const payer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath)))
  );

  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  const programId = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
  const pool = Keypair.generate().publicKey; // test pool

  const [guardConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard_config"), payer.publicKey.toBuffer()],
    programId
  );
  const [poolGuardState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_guard_state"), pool.toBuffer()],
    programId
  );

  // discriminator for heartbeat
  const disc = Buffer.from([202, 104, 56, 6, 240, 170, 63, 134]);
  const data = Buffer.concat([disc, pool.toBuffer()]);

  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: payer.publicKey,  isSigner: true,  isWritable: true },
      { pubkey: guardConfig,      isSigner: false, isWritable: false },
      { pubkey: poolGuardState,   isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(ix);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);

  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, "confirmed");

  console.log("✅ Heartbeat sent!");
  console.log("Pool:          ", pool.toBase58());
  console.log("PoolGuardState:", poolGuardState.toBase58());
  console.log("TX:", sig);
}

main().catch(console.error);
