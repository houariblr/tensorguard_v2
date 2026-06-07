use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    sysvar::instructions as ix_sysvar,
    ed25519_program,
};
use crate::state::{AggregatedAttestation, GuardConfig, PoolGuardState, Verdict};
use crate::errors::TensorGuardError;

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct AggregatedArgs {
    pub pool:            Pubkey,
    pub nonce:           u64,
    pub verdict:         Verdict,
    pub confidence_bps:  u16,
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,
    pub signer_bitmask:  u8,
    /// 64-byte Ed25519 FROST aggregated signature
    pub agg_signature:   [u8; 64],
}

#[derive(Accounts)]
#[instruction(args: AggregatedArgs)]
pub struct PostAggregated<'info> {
    /// Coordinator — must be a trusted signer
    #[account(
        mut,
        constraint = guard_config.is_trusted(&coordinator.key())
            @ TensorGuardError::UntrustedSigner
    )]
    pub coordinator: Signer<'info>,

    #[account(
        seeds = [b"guard_config", guard_config.authority.as_ref()],
        bump  = guard_config.bump,
        constraint = guard_config.active @ TensorGuardError::GuardInactive
    )]
    pub guard_config: Account<'info, GuardConfig>,

    #[account(
        init,
        payer = coordinator,
        space = AggregatedAttestation::LEN,
        seeds = [
            b"agg_attestation",
            args.pool.as_ref(),
            &args.nonce.to_le_bytes()
        ],
        bump
    )]
    pub attestation: Account<'info, AggregatedAttestation>,

    #[account(
        mut,
        seeds = [b"pool_guard_state", args.pool.as_ref()],
        bump  = pool_guard_state.bump,
    )]
    pub pool_guard_state: Account<'info, PoolGuardState>,

    /// Instructions sysvar — used to verify the ed25519 precompile ran
    /// CHECK: verified by address constraint
    #[account(address = ix_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Canonical message encoding — must match tensorguard-multisig exactly
fn encode_attestation_msg(args: &AggregatedArgs) -> [u8; 55] {
    let mut msg = [0u8; 55];
    msg[0..32].copy_from_slice(args.pool.as_ref());
    msg[32..40].copy_from_slice(&args.nonce.to_le_bytes());
    msg[40] = if args.verdict == Verdict::Attack { 1 } else { 0 };
    msg[41..43].copy_from_slice(&args.confidence_bps.to_le_bytes());
    msg[43..47].copy_from_slice(&args.lyapunov_x100.to_le_bytes());
    msg[47..51].copy_from_slice(&args.kolmogorov_x100.to_le_bytes());
    msg[51..55].copy_from_slice(&args.ricci_x100.to_le_bytes());
    msg
}

pub fn handler(ctx: Context<PostAggregated>, args: AggregatedArgs) -> Result<()> {
    let clock = Clock::get()?;

    // ── 1. Bitmask threshold check ────────────────────────────────────────────
    let signer_count = args.signer_bitmask.count_ones() as u8;
    require!(
        signer_count >= ctx.accounts.guard_config.threshold,
        TensorGuardError::BelowThreshold
    );

    // ── 2. Ed25519 signature verification ────────────────────────────────────
    // We require the transaction to include an ed25519_program instruction
    // that verified: verify(group_pubkey, message, agg_signature)
    //
    // The coordinator builds the tx as:
    //   ix[0]: ed25519_program::new_ed25519_instruction(group_pk, msg, sig)
    //   ix[1]: this post_aggregated instruction
    //
    // We check that ix[0] verified our exact message + group pubkey.
    verify_ed25519_precompile(
        &ctx.accounts.instructions_sysvar,
        &ctx.accounts.guard_config.group_pubkey,
        &encode_attestation_msg(&args),
        &args.agg_signature,
    )?;

    // ── 3. Store attestation ──────────────────────────────────────────────────
    let att = &mut ctx.accounts.attestation;
    att.pool            = args.pool;
    att.nonce           = args.nonce;
    att.slot            = clock.slot;
    att.verdict         = args.verdict;
    att.confidence_bps  = args.confidence_bps;
    att.lyapunov_x100   = args.lyapunov_x100;
    att.kolmogorov_x100 = args.kolmogorov_x100;
    att.ricci_x100      = args.ricci_x100;
    att.signer_bitmask  = args.signer_bitmask;
    att.agg_signature   = args.agg_signature;
    att.bump            = ctx.bumps.attestation;

    ctx.accounts.pool_guard_state.last_daemon_activity_slot = clock.slot;

    msg!(
        "[agg] pool:{} nonce:{} verdict:{} signers:{} ({:08b}) ✓ ed25519",
        att.pool, att.nonce,
        if att.verdict == Verdict::Attack { "ATTACK" } else { "SAFE" },
        signer_count,
        att.signer_bitmask,
    );

    Ok(())
}

/// Verify that a prior ed25519_program instruction in this transaction
/// verified our exact (pubkey, message, signature) triple.
///
/// This is the standard Solana pattern for on-chain signature verification.
/// Cost: ~400 CU (just reading the Instructions sysvar)
fn verify_ed25519_precompile(
    ix_sysvar:   &UncheckedAccount,
    group_pubkey: &[u8; 32],
    message:      &[u8; 55],
    signature:    &[u8; 64],
) -> Result<()> {
    // Load the ed25519 instruction from the Instructions sysvar
    let ix = ix_sysvar::get_instruction_relative(-1, &ix_sysvar.to_account_info())
        .map_err(|_| TensorGuardError::WrongSigner)?;

    // Must be the native ed25519 program
    require_keys_eq!(ix.program_id, ed25519_program::ID, TensorGuardError::WrongSigner);

    // ed25519 instruction data layout:
    // [num_sigs:1][pad:1][sig_offset:2][sig_ix:2][pk_offset:2][pk_ix:2]
    // [msg_offset:2][msg_size:2][msg_ix:2]...[signatures][pubkeys][messages]
    let data = &ix.data;
    require!(data.len() >= 16, TensorGuardError::WrongSigner);

    // Extract offsets (little-endian u16)
    let sig_offset = u16::from_le_bytes([data[2], data[3]]) as usize;
    let pk_offset  = u16::from_le_bytes([data[6], data[7]]) as usize;
    let msg_offset = u16::from_le_bytes([data[10], data[11]]) as usize;
    let msg_size   = u16::from_le_bytes([data[12], data[13]]) as usize;

    // Bounds check
    require!(
        data.len() >= sig_offset + 64
            && data.len() >= pk_offset + 32
            && data.len() >= msg_offset + msg_size,
        TensorGuardError::WrongSigner
    );

    // Verify our signature matches
    require!(
        &data[sig_offset..sig_offset + 64] == signature.as_ref(),
        TensorGuardError::WrongSigner
    );

    // Verify our public key matches
    require!(
        &data[pk_offset..pk_offset + 32] == group_pubkey.as_ref(),
        TensorGuardError::WrongSigner
    );

    // Verify our message matches
    require!(
        msg_size == message.len()
            && &data[msg_offset..msg_offset + msg_size] == message.as_ref(),
        TensorGuardError::WrongSigner
    );

    Ok(())
}
