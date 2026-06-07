use borsh::BorshSerialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use tensorguard_core::AttackSignal;

/// Anchor instruction discriminator = first 8 bytes of SHA256("global:post_attestation")
/// Compute once with: `echo -n "global:post_attestation" | sha256sum | cut -c1-16`
/// Pre-computed: [132, 71, 196, 201, 214, 163, 72, 89]
const POST_AGGREGATED_DISCRIMINATOR: [u8; 8] = [89, 99, 3, 196, 67, 157, 165, 80]; // sha256("global:post_aggregated")[0..8]

/// Mirrors AttestationArgs from the Anchor program
#[derive(BorshSerialize)]
struct AttestationArgs {
    pool:             [u8; 32],
    verdict:          u8,        // 0 = Safe, 1 = Attack
    confidence_bps:   u16,
    lyapunov_x100:    u32,
    kolmogorov_x100:  u32,
    ricci_x100:       u32,
    nonce:            u64,
}

pub struct AttestationSender {
    pub program_id:    Pubkey,
    pub authority:     Pubkey,
    pub daemon_kp:     Keypair,
    pub nonce:         u64,
}

impl AttestationSender {
    pub fn new(program_id: Pubkey, authority: Pubkey, daemon_kp: Keypair) -> Self {
        Self { program_id, authority, daemon_kp, nonce: 0 }
    }

    /// Derive the GuardConfig PDA
    fn guard_config_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"guard_config", self.authority.as_ref()],
            &self.program_id,
        )
    }

    /// Derive the Attestation PDA for (pool, nonce)
    fn attestation_pda(&self, pool: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"attestation", pool.as_ref(), &self.nonce.to_le_bytes()],
            &self.program_id,
        )
    }

    /// Build and send a post_attestation transaction
    pub fn send(
        &mut self,
        rpc: &RpcClient,
        pool: &Pubkey,
        signal: &AttackSignal,
    ) -> Result<(), String> {
        self.nonce += 1;

        let (guard_config, _) = self.guard_config_pda();
        let (attestation_pda, _) = self.attestation_pda(pool);

        // Scale floats → fixed integers for on-chain storage
        let lyapunov_x100   = (signal.lyapunov   * 100.0).min(u32::MAX as f64) as u32;
        let kolmogorov_x100 = (signal.kolmogorov * 100.0).min(u32::MAX as f64) as u32;
        let ricci_x100      = (signal.ricci       * 100.0).min(u32::MAX as f64) as u32;
        let confidence_bps  = (signal.confidence  * 10_000.0).min(10_000.0) as u16;
        let verdict: u8     = if signal.is_attack { 1 } else { 0 };

        let args = AttestationArgs {
            pool:            pool.to_bytes(),
            verdict,
            confidence_bps,
            lyapunov_x100,
            kolmogorov_x100,
            ricci_x100,
            nonce:           self.nonce,
        };

        // Build instruction data: discriminator ++ borsh(args)
        let mut ix_data = POST_AGGREGATED_DISCRIMINATOR.to_vec();
        args.serialize(&mut ix_data).map_err(|e| e.to_string())?;

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.daemon_kp.pubkey(), true), // daemon (signer + payer)
                AccountMeta::new_readonly(guard_config, false),
                AccountMeta::new(attestation_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            data: ix_data,
        };

        let recent_blockhash = rpc.get_latest_blockhash()
            .map_err(|e| e.to_string())?;

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.daemon_kp.pubkey()),
            &[&self.daemon_kp],
            recent_blockhash,
        );

        rpc.send_and_confirm_transaction(&tx)
            .map_err(|e| e.to_string())?;

        println!(
            "[attestation] sent | nonce:{} | verdict:{} | confidence:{:.1}%",
            self.nonce,
            if signal.is_attack { "ATTACK" } else { "SAFE" },
            signal.confidence * 100.0,
        );

        Ok(())
    }
}
