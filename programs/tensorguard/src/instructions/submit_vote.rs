use anchor_lang::prelude::*;
use crate::state::{GuardConfig, Vote, VoteAccount, Verdict};
use crate::errors::TensorGuardError;

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VoteArgs {
    pub pool:            Pubkey,
    pub verdict:         Verdict,
    pub confidence_bps:  u16,
    pub lyapunov_x100:   u32,
    pub kolmogorov_x100: u32,
    pub ricci_x100:      u32,
    pub nonce:           u64,
}

#[derive(Accounts)]
#[instruction(args: VoteArgs)]
pub struct SubmitVote<'info> {
    /// One of the trusted daemon nodes
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

    #[account(
        init_if_needed,
        payer = daemon,
        space = VoteAccount::LEN,
        seeds = [
            b"vote_account",
            args.pool.as_ref(),
            &args.nonce.to_le_bytes()
        ],
        bump
    )]
    pub vote_account: Account<'info, VoteAccount>,

    pub system_program: Program<'info, System>,
}

/// Each daemon calls this independently.
/// When votes >= threshold → auto-finalize with majority verdict.
pub fn handler(ctx: Context<SubmitVote>, args: VoteArgs) -> Result<()> {
    let va = &mut ctx.accounts.vote_account;

    // --- Guard: already finalized ---
    require!(!va.finalized, TensorGuardError::AlreadyFinalized);

    // --- Guard: no double voting ---
    let daemon_key = ctx.accounts.daemon.key();
    require!(
        !va.votes.iter().any(|v| v.signer == daemon_key),
        TensorGuardError::AlreadyVoted
    );

    // --- First voter initializes the account fields ---
    if va.votes.is_empty() {
        let clock = Clock::get()?;
        va.pool      = args.pool;
        va.nonce     = args.nonce;
        va.slot      = clock.slot;
        va.finalized = false;
        va.verdict   = Verdict::Safe; // placeholder until finalized
        va.bump      = ctx.bumps.vote_account;
    }

    // --- Record this vote ---
    va.votes.push(Vote {
        signer:          daemon_key,
        verdict:         args.verdict.clone(),
        confidence_bps:  args.confidence_bps,
        lyapunov_x100:   args.lyapunov_x100,
        kolmogorov_x100: args.kolmogorov_x100,
        ricci_x100:      args.ricci_x100,
    });

    msg!(
        "[vote] daemon: {} | verdict: {} | votes so far: {}/{}",
        daemon_key,
        if args.verdict == Verdict::Attack { "ATTACK" } else { "SAFE" },
        va.votes.len(),
        ctx.accounts.guard_config.threshold
    );

    // --- Auto-finalize when threshold reached ---
    if va.votes.len() >= ctx.accounts.guard_config.threshold as usize {
        va.finalize();
        msg!(
            "[finalized] pool: {} | verdict: {} | confidence: {}bps",
            va.pool,
            if va.verdict == Verdict::Attack { "ATTACK" } else { "SAFE" },
            va.confidence_bps
        );
    }

    Ok(())
}
