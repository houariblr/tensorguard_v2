use borsh::BorshSerialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
    system_program,
};

/// Anchor discriminator for `heartbeat` instruction
/// sha256("global:heartbeat")[0..8]
const HEARTBEAT_DISCRIMINATOR: [u8; 8] = [202, 104, 56, 6, 240, 170, 63, 134]; // sha256("global:heartbeat")[0..8]

pub async fn send_heartbeat(
    rpc:        &RpcClient,
    program_id: &Pubkey,
    daemon_kp:  &Keypair,
    authority:  &Pubkey,
    pool:       &Pubkey,
) -> Result<(), String> {
    let (guard_config, _) = Pubkey::find_program_address(
        &[b"guard_config", authority.as_ref()],
        program_id,
    );
    let (pool_guard_state, _) = Pubkey::find_program_address(
        &[b"pool_guard_state", pool.as_ref()],
        program_id,
    );

    // Instruction data: discriminator ++ borsh(pool: Pubkey)
    let mut ix_data = HEARTBEAT_DISCRIMINATOR.to_vec();
    pool.to_bytes().serialize(&mut ix_data).map_err(|e| e.to_string())?;

    let ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(daemon_kp.pubkey(), true),
            AccountMeta::new_readonly(guard_config, false),
            AccountMeta::new(pool_guard_state, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: ix_data,
    };

    let blockhash = rpc.get_latest_blockhash().map_err(|e| e.to_string())?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&daemon_kp.pubkey()),
        &[daemon_kp],
        blockhash,
    );

    rpc.send_and_confirm_transaction(&tx).map_err(|e| e.to_string())?;
    println!("[heartbeat] ✓ pool: {}", pool);
    Ok(())
}
