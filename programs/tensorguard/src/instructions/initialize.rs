use anchor_lang::prelude::*;
use crate::state::GuardConfig;
use crate::errors::TensorGuardError;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = GuardConfig::LEN,
        seeds = [b"guard_config", authority.key().as_ref()],
        bump
    )]
    pub guard_config: Account<'info, GuardConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Deploy the guard with initial signers and threshold.
/// Example: signers=[A,B,C], threshold=2 → any 2 of 3 daemons can finalize
pub fn handler(
    ctx: Context<Initialize>,
    initial_signers: Vec<Pubkey>,
    threshold: u8,
    group_pubkey: [u8; 32],
) -> Result<()> {
    require!(
        initial_signers.len() <= crate::state::VoteAccount::MAX_SIGNERS,
        TensorGuardError::SignersFull
    );
    require!(
        threshold as usize <= initial_signers.len() && threshold > 0,
        TensorGuardError::BelowThreshold
    );

    let config = &mut ctx.accounts.guard_config;
    config.authority = ctx.accounts.authority.key();
    config.signers   = initial_signers.clone();
    config.threshold = threshold;
    config.group_pubkey = group_pubkey;
    config.active    = true;
    config.bump      = ctx.bumps.guard_config;

    msg!(
        "TensorGuard initialized | {}/{} multisig | signers: {:?}",
        threshold,
        initial_signers.len(),
        initial_signers
    );
    Ok(())
}
