use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

use instructions::{
    initialize::*,
    submit_vote::*,
    post_aggregated::*,
    guard_verify::*,
    manage_signers::*,
    heartbeat::*,
};

declare_id!("5pz6CWu6VmE3RuU1sAx7wVP43BxYkDTNCq4ZPECGFSBG");

#[program]
pub mod tensorguard {
    use super::*;

    /// Deploy guard: set initial signers + threshold (e.g. 2/3)
    pub fn initialize(
        ctx: Context<Initialize>,
        initial_signers: Vec<Pubkey>,
        threshold: u8,
        group_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::initialize::handler(ctx, initial_signers, threshold, group_pubkey)
    }

    // ── Voting paths ──────────────────────────────────────────────────────────

    /// [Legacy] Individual daemon vote — on-chain aggregation
    /// Use this for devnet testing or when coordinator is unavailable
    pub fn submit_vote(ctx: Context<SubmitVote>, args: VoteArgs) -> Result<()> {
        instructions::submit_vote::handler(ctx, args)
    }

    /// [Production] Coordinator posts single BLS-aggregated attestation
    /// ONE transaction replaces N submit_vote transactions
    /// CU cost: ~3,500 vs ~15,000 for on-chain voting
    pub fn post_aggregated(
        ctx: Context<PostAggregated>,
        args: AggregatedArgs,
    ) -> Result<()> {
        instructions::post_aggregated::handler(ctx, args)
    }

    // ── Guard gate ────────────────────────────────────────────────────────────

    /// AMM calls this before every swap — PASS / REVERT / FALLBACK
    pub fn guard_verify(ctx: Context<GuardVerify>) -> Result<()> {
        instructions::guard_verify::handler(ctx)
    }

    // ── Liveness ──────────────────────────────────────────────────────────────

    /// Daemon posts heartbeat every ~20 slots to prevent fallback mode
    pub fn heartbeat(ctx: Context<Heartbeat>, pool: Pubkey) -> Result<()> {
        instructions::heartbeat::handler(ctx, pool)
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    pub fn add_signer(ctx: Context<ManageSigners>, signer: Pubkey) -> Result<()> {
        instructions::manage_signers::add_signer(ctx, signer)
    }

    pub fn remove_signer(ctx: Context<ManageSigners>, signer: Pubkey) -> Result<()> {
        instructions::manage_signers::remove_signer(ctx, signer)
    }

    pub fn set_threshold(ctx: Context<ManageSigners>, threshold: u8) -> Result<()> {
        instructions::manage_signers::set_threshold(ctx, threshold)
    }

    pub fn set_active(ctx: Context<ManageSigners>, active: bool) -> Result<()> {
        ctx.accounts.guard_config.active = active;
        msg!("TensorGuard active: {}", active);
        Ok(())
    }
}
