use anchor_lang::prelude::*;

#[error_code]
pub enum TensorGuardError {
    #[msg("Signer is not in the trusted set")]
    UntrustedSigner,

    #[msg("Ed25519 instruction signer does not match group_pubkey")]
    UnauthorizedSigner,

    #[msg("Ed25519 instruction data is malformed or too short")]
    InvalidInstructionData,

    #[msg("Signer already voted on this nonce")]
    AlreadyVoted,

    #[msg("VoteAccount is already finalized")]
    AlreadyFinalized,

    #[msg("VoteAccount is not yet finalized — threshold not reached")]
    NotFinalized,

    #[msg("Attestation is stale — too many slots have passed")]
    StaleAttestation,

    #[msg("Attestation is for a different pool")]
    WrongPool,

    #[msg("TensorGuard blocked this transaction: attack detected")]
    AttackDetected,

    #[msg("Signers list is full (max 5)")]
    SignersFull,

    #[msg("Signer already exists in trusted set")]
    SignerAlreadyExists,

    #[msg("Cannot remove signer — would fall below threshold")]
    BelowThreshold,

    #[msg("Guard is not active")]
    GuardInactive,

    #[msg("Unauthorized: caller is not the authority")]
    Unauthorized,

    #[msg("Wrong signer for this instruction")]
    WrongSigner,
}
