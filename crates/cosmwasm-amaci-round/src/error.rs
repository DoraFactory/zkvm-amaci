use cosmwasm_std::StdError;
use thiserror::Error;

use crate::msg::RoundStage;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("SP1 compressed verification failed: {reason}")]
    CompressedVerification { reason: String },

    #[error("round is already complete")]
    RoundComplete,

    #[error("stage out of order: expected {expected:?}, got {actual:?}")]
    StageOutOfOrder {
        expected: RoundStage,
        actual: RoundStage,
    },

    #[error("round plan must include at least one proof stage")]
    EmptyRoundPlan,
}
