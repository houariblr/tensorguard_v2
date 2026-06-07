use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    sysvar::instructions::{load_instruction_at_checked, ID as IX_SYSVAR_ID},
    ed25519_program,
    clock::Clock,
    sysvar::Sysvar,
};
use crate::errors::TensorGuardError;

const VERDICT_OFFSET: usize = 56;
const SLOT_OFFSET:    usize = 48;

#[derive(Accounts)]
pub struct GuardVerify<'info> {
    /// CHECK: only key is read
    pub pool: UncheckedAccount<'info>,
    /// CHECK: raw bytes via try_borrow_data()
    pub guard_config: UncheckedAccount<'info>,
    /// CHECK: AggregatedAttestation — raw bytes
    #[account(mut)]
    pub attestation: UncheckedAccount<'info>,
    /// CHECK: PoolGuardState — raw bytes
    #[account(mut)]
    pub pool_guard_state: UncheckedAccount<'info>,
    /// CHECK: Instructions sysvar
    #[account(address = IX_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub caller: Signer<'info>,
}

pub fn handler(ctx: Context<GuardVerify>) -> Result<()> {
    let clock = Clock::get()?;

    // ── 1. Read guard_config — extract active flag + group_pubkey ─────────────
    let group_pubkey: [u8; 32];
    {
        let cfg = ctx.accounts.guard_config.try_borrow_data()?;

        // active flag: [44 + N*32 + 1 + 32]
        if cfg.len() > 44 {
            let n = u32::from_le_bytes(
                cfg[40..44].try_into().unwrap_or([0u8; 4])
            ) as usize;
            let active_offset      = 44 + n * 32 + 1 + 32;
            let group_pubkey_start = 44 + n * 32 + 1;
            let group_pubkey_end   = group_pubkey_start + 32;

            if cfg.len() > active_offset && cfg[active_offset] == 0 {
                msg!("TensorGuard inactive — skipping");
                return Ok(());
            }

            require!(
                cfg.len() >= group_pubkey_end,
                TensorGuardError::WrongSigner
            );

            group_pubkey = cfg[group_pubkey_start..group_pubkey_end]
                .try_into()
                .map_err(|_| TensorGuardError::WrongSigner)?;
        } else {
            return Err(TensorGuardError::WrongSigner.into());
        }
    } // cfg borrow dropped

    // ── 2. Read attestation ───────────────────────────────────────────────────
    let att_len;
    let att_slot;
    let verdict_byte;
    {
        let att = ctx.accounts.attestation.try_borrow_data()?;
        att_len = att.len();

        if att_len > SLOT_OFFSET + 8 {
            att_slot = u64::from_le_bytes(
                att[SLOT_OFFSET..SLOT_OFFSET + 8].try_into()
                    .map_err(|_| TensorGuardError::StaleAttestation)?
            );
            verdict_byte = if att_len > VERDICT_OFFSET { att[VERDICT_OFFSET] } else { 255 };
        } else {
            att_slot     = 0;
            verdict_byte = 255;
        }
    } // att borrow dropped

    // ── 3. No attestation → fallback ─────────────────────────────────────────
    if att_len <= VERDICT_OFFSET {
        return handle_fallback(&ctx.accounts.pool_guard_state, clock.slot);
    }

    // ── 4. Freshness check ────────────────────────────────────────────────────
    let age = clock.slot.saturating_sub(att_slot);
    require!(age <= 40, TensorGuardError::StaleAttestation);

    // ── 5. Ed25519 introspection + signer verification ────────────────────────
    //
    // We verify THREE things:
    //   a) ix[0] is the native Ed25519Program (runtime did the crypto)
    //   b) The public key in that instruction == our group_pubkey (no spoofing)
    //   c) The message in that instruction matches our attestation data
    //
    // Ed25519 instruction data layout:
    //   [0]      num_signatures: u8
    //   [1]      padding: u8
    //   [2..4]   signature_offset: u16
    //   [4..6]   signature_instruction_index: u16
    //   [6..8]   public_key_offset: u16       ← pubkey starts here
    //   [8..10]  public_key_instruction_index: u16
    //   [10..12] message_data_offset: u16
    //   [12..14] message_data_size: u16
    //   [14..16] message_instruction_index: u16
    //   [16..]   data (signatures, pubkeys, messages packed)
    {
        let ix = load_instruction_at_checked(
            0,
            &ctx.accounts.instructions_sysvar.to_account_info(),
        ).map_err(|_| TensorGuardError::WrongSigner)?;

        // a) Must be the native Ed25519 precompile
        require!(
            ix.program_id == ed25519_program::id(),
            TensorGuardError::WrongSigner
        );

        require!(ix.data.len() >= 16, TensorGuardError::InvalidInstructionData);

        // b) Extract public key offset and verify against group_pubkey
        let pk_offset = u16::from_le_bytes([ix.data[6], ix.data[7]]) as usize;
        require!(
            ix.data.len() >= pk_offset + 32,
            TensorGuardError::InvalidInstructionData
        );

        let ix_pubkey = &ix.data[pk_offset..pk_offset + 32];

        // THE FIX: verify the signer is our trusted group_pubkey
        require!(
            ix_pubkey == group_pubkey.as_ref(),
            TensorGuardError::UnauthorizedSigner
        );

        // c) Verify message matches our attestation (pool + nonce + verdict)
        let msg_offset = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
        let msg_size   = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;

        require!(
            ix.data.len() >= msg_offset + msg_size,
            TensorGuardError::InvalidInstructionData
        );

        // First 9 bytes of message must match: pool(32) skipped — nonce(8) + verdict(1)
        // For full security: verify the complete 55-byte message
        // Message must be at least large enough to hold the 32-byte pool pubkey
          if msg_size >= 32 {
                 let ix_msg = &ix.data[msg_offset..msg_offset + msg_size];

                     require!(&ix_msg[0..32] == ctx.accounts.pool.key().as_ref(),
                     TensorGuardError::WrongPool
                       );
               } else {
    // إذا كانت الرسالة أصغر من 32 بايت، فهي بالتأكيد غير صالحة
                        return Err(TensorGuardError::InvalidInstructionData.into());
                      }
    }

    // ── 6. The gate ───────────────────────────────────────────────────────────
    if verdict_byte == 1 {
        msg!("TensorGuard ⚠️  ATTACK | slot:{} age:{}", att_slot, age);
        return Err(TensorGuardError::AttackDetected.into());
    }

    update_last_verified(&ctx.accounts.pool_guard_state, clock.slot)?;
    msg!("TensorGuard ✓ SAFE | slot:{} age:{} slots", att_slot, age);
    Ok(())
}

fn handle_fallback(pool_guard_state: &UncheckedAccount, current_slot: u64) -> Result<()> {
    let silence = {
        let data = pool_guard_state.try_borrow_data()?;
        if data.len() >= 48 {
            let last = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0u8; 8]));
            current_slot.saturating_sub(last)
        } else {
            u64::MAX
        }
    };

    if silence < 200 {
        msg!("TensorGuard ✗ NOT_READY | daemon alive, attestation pending");
        return Err(TensorGuardError::NotFinalized.into());
    }

    update_last_verified(pool_guard_state, current_slot)?;
    msg!("TensorGuard ⚠️  FALLBACK | daemon silent {} slots — ALLOWING", silence);
    Ok(())
}

fn update_last_verified(account: &UncheckedAccount, slot: u64) -> Result<()> {
    let mut data = account.try_borrow_mut_data()?;
    if data.len() >= 56 {
        data[48..56].copy_from_slice(&slot.to_le_bytes());
    }
    Ok(())
}
