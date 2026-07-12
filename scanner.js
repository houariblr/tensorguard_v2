const { Connection, PublicKey } = require('@solana/web3.js');

// إعداد الاتصال
const RPC_ENDPOINT = 'https://api.mainnet-beta.solana.com';
const connection = new Connection(RPC_ENDPOINT, 'confirmed');
const POOL_ADDRESS = new PublicKey('7JuwJuNU88gurFnyWeiyGKbFmExMWcmRZntn9imEzdny');

async function inspectAccount() {
    console.log("--- TensorGuard Memory Inspector ---");
    console.log("Inspecting Address:", POOL_ADDRESS.toBase58());

    try {
        const acc = await connection.getAccountInfo(POOL_ADDRESS);
        
        if (!acc) {
            console.log("Account not found or empty.");
            return;
        }

        console.log("Program Owner:", acc.owner.toBase58());
        console.log("Data Length:", acc.data.length, "bytes\n");

        // عرض البيانات الخام
        console.log("--- Hex Data Dump ---");
        console.log(acc.data.toString('hex').substring(0, 256) + "...");
        console.log("\n--- Offset Analysis (First 128 bytes) ---");
        
        // تحليل الذاكرة كـ 64-bit Integers
        for (let i = 0; i < 128; i += 8) {
            const val64 = acc.data.readBigUInt64LE(i);
            const val32 = acc.data.readUInt32LE(i);
            
            process.stdout.write(
                `Offset ${i.toString().padEnd(3)} | ` +
                `U64: ${val64.toString().padEnd(20)} | ` +
                `U32: ${val32.toString().padEnd(10)}\n`
            );
        }

    } catch (err) {
        console.error("Inspector Error:", err.message);
    }
}

inspectAccount();