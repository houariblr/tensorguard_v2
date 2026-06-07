use anchor_lang::prelude::*;
use crate::state::{GuardConfig, PoolGuardState};
use crate::errors::TensorGuardError;

#[derive(Accounts)]
#[instruction(pool: Pubkey)]
pub struct Heartbeat<'info> {
    #[account(
        mut,
        constraint = guard_config.is_trusted(&daemon.key())
            @ TensorGuardError::UntrustedSigner
    )]
    pub daemon: Signer<'info>,

    #[account(
        seeds = [b"guard_config", guard_config.authority.as_ref()],
        bump  = guard_config.bump,
        constraint = guard_config.active @ TensorGuardError::GuardInactive
    )]
    pub guard_config: Account<'info, GuardConfig>,

    /// Init on first heartbeat for this pool, update thereafter
    #[account(
        init_if_needed,
        payer = daemon,
        space = PoolGuardState::LEN,
        seeds = [b"pool_guard_state", pool.as_ref()],
        bump
    )]
    pub pool_guard_state: Account<'info, PoolGuardState>,

    pub system_program: Program<'info, System>,
}

/// Daemon posts a heartbeat every ~20 slots (~8 seconds).
/// Keeps PoolGuardState.last_daemon_activity_slot fresh.
/// guard_verify reads this to decide whether to enter fallback mode.
pub fn handler(ctx: Context<Heartbeat>, pool: Pubkey) -> Result<()> {
    let state = &mut ctx.accounts.pool_guard_state;
    let clock = Clock::get()?;

    // First heartbeat — initialize the account
    if state.pool == Pubkey::default() {
        state.pool       = pool;
        state.bump       = ctx.bumps.pool_guard_state;
        state.fallback_count = 0;
        state.last_verified_slot = 0;
    }

    state.last_daemon_activity_slot = clock.slot;

    msg!(
        "[heartbeat] daemon: {} | pool: {} | slot: {}",
        ctx.accounts.daemon.key(),
        pool,
        clock.slot
    );

    Ok(())
}
