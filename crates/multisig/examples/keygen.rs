//! keygen — generate FROST key shares and write to disk
//!
//! Usage:
//!   cargo run -p tensorguard-multisig --example keygen -- \
//!     --threshold 2 --num-signers 3 --output ./keys/

use std::{env, fs, path::Path};
use tensorguard_multisig::generate_key_shares;

fn main() {
    let args: Vec<String> = env::args().collect();

    let threshold   = parse_arg(&args, "--threshold",   2u16);
    let num_signers = parse_arg(&args, "--num-signers",  3u16);
    let output_dir  = parse_str(&args, "--output",       "./keys");

    println!("Generating FROST {threshold}-of-{num_signers} key shares → {output_dir}");

    let result = generate_key_shares(threshold, num_signers)
        .expect("keygen failed");

    fs::create_dir_all(&output_dir).expect("could not create output dir");

    // ── group_pubkey.hex ────────────────────────────────────────────────────
    let hex: String = result.group_pubkey.iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    write_file(&output_dir, "group_pubkey.hex", &hex);
    println!("  group_pubkey.hex       : {hex}");

    // ── daemon_N.key (frost-serialized, hex-encoded) ─────────────────────────
    for (i, (_id, kp)) in result.key_packages.iter().enumerate() {
        let n = i + 1;
        let bytes = kp.serialize().expect("serialize KeyPackage");
        let kp_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        write_file(&output_dir, &format!("daemon_{n}.key"), &kp_hex);
        println!("  daemon_{n}.key             : {} raw bytes (hex)", bytes.len());
    }

    // ── pubkey_package.json ─────────────────────────────────────────────────
    let pk_bytes = result.pubkey_package.verifying_key()
        .serialize().expect("serialize group pubkey");
    let pk_hex: String = pk_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let json = format!("{{\"group_pubkey\":\"{pk_hex}\"}}");
    write_file(&output_dir, "pubkey_package.json", &json);
    println!("  pubkey_package.json    : group_pubkey={pk_hex}");

    println!("\nDone ✅");
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn write_file(dir: &str, name: &str, content: &str) {
    let path = Path::new(dir).join(name);
    fs::write(&path, content).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> T
where T::Err: std::fmt::Debug {
    args.windows(2)
        .find(|w| w[0] == flag)
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(default)
}

fn parse_str(args: &[String], flag: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}
