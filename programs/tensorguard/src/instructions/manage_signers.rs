use anchor_lang::prelude::*;
use crate::state::GuardConfig;
use crate::errors::TensorGuardError;

#[derive(Accounts)]
pub struct ManageSigners<'info> {
    #[account(
        mut,
        seeds = [b"guard_config", authority.key().as_ref()],
        bump  = guard_config.bump,
        constraint = guard_config.authority == authority.key()
            @ TensorGuardError::Unauthorized
    )]
    pub guard_config: Account<'info, GuardConfig>,
    pub authority: Signer<'info>,
}

/// Add a new daemon to the trusted set
pub fn add_signer(ctx: Context<ManageSigners>, signer: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.guard_config;
    require!(
        config.signers.len() < crate::state::VoteAccount::MAX_SIGNERS,
        TensorGuardError::SignersFull
    );
    require!(
        !config.signers.contains(&signer),
        TensorGuardError::SignerAlreadyExists
    );
    config.signers.push(signer);
    msg!("Signer added: {} | total: {}", signer, config.signers.len());
    Ok(())
}

/// Remove a daemon from the trusted set
pub fn remove_signer(ctx: Context<ManageSigners>, signer: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.guard_config;
    require!(
        (config.signers.len() - 1) >= config.threshold as usize,
        TensorGuardError::BelowThreshold
    );
    config.signers.retain(|s| s != &signer);
    msg!("Signer removed: {} | remaining: {}", signer, config.signers.len());
    Ok(())
}

/// Update threshold (e.g. 2/3 → 3/4 after adding a new daemon)
pub fn set_threshold(ctx: Context<ManageSigners>, threshold: u8) -> Result<()> {
    let config = &mut ctx.accounts.guard_config;
    require!(
        (threshold as usize) <= config.signers.len() && threshold > 0,
        TensorGuardError::BelowThreshold
    );
    config.threshold = threshold;
    msg!("Threshold updated: {}/{}", threshold, config.signers.len());
    Ok(())
}
