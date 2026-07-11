use cosmwasm_std::StdError;
use thiserror::Error;

use crate::msg::{RoundPhase, RoundStage};

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("SP1 compressed verification failed: {reason}")]
    CompressedVerification { reason: String },

    #[error("unauthorized operator action")]
    Unauthorized,

    #[error("round phase mismatch: expected {expected:?}, got {actual:?}")]
    PhaseMismatch {
        expected: RoundPhase,
        actual: RoundPhase,
    },

    #[error("online proof stage is not supported: {stage:?}")]
    UnsupportedOnlineStage { stage: RoundStage },

    #[error("round plan must include post-round process-messages and tally proofs")]
    InvalidRoundPlan,

    #[error("online proof counter overflow: {stage:?}")]
    OnlineCounterOverflow { stage: RoundStage },

    #[error("config field {field} must be 32 bytes, got {actual}")]
    InvalidConfigLength { field: String, actual: usize },

    #[error("invalid public output: {reason}")]
    InvalidPublicOutput { reason: String },

    #[error("public output is for {actual:?}, expected {expected:?}")]
    PublicOutputStageMismatch {
        expected: RoundStage,
        actual: RoundStage,
    },

    #[error("proof identity mismatch: {field}")]
    IdentityMismatch { field: String },

    #[error("deactivate transition mismatch: {field}")]
    DeactivateTransitionMismatch { field: String },

    #[error("add-new-key references an unverified deactivate root")]
    UnknownDeactivateRoot,

    #[error("add-new-key nullifier was already used")]
    NullifierAlreadyUsed,

    #[error("finalization plan mismatch: {reason}")]
    FinalizationPlanMismatch { reason: String },

    #[error("finalization checkpoint mismatch: {field}")]
    FinalizationCheckpointMismatch { field: String },
}
