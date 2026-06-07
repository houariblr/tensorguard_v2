// post_aggregated_attack.js — يخزن attestation بـ verdict=Attack (nonce=2)
const { Connection, PublicKey, Keypair, Transaction,
        TransactionInstruction, SystemProgram } = require("@solana/web3.js");
const fs = require("fs");
const nacl = require("tweetnacl");

const PROGRAM_ID  = new PublicKey("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");
const POOL_PUBKEY = new PublicKey("FBg8i1mBnv6ax1UPam8BeJXAGJn4THXJDtVRiFNd78fg");
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