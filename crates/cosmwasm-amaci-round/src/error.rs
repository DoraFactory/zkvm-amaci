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

    #[error("aggregate stage is not supported: {stage:?}")]
    UnsupportedAggregateStage { stage: RoundStage },

    #[error("aggregate public output stage mismatch: expected {expected:?}, got {actual:?}")]
    AggregateStageMismatch {
        expected: RoundStage,
        actual: RoundStage,
    },

    #[error("invalid aggregate public output: {reason}")]
    InvalidAggregatePublicOutput { reason: String },

    #[error("aggregate child count exceeds remaining stage count: remaining {remaining}, child_count {child_count}")]
    AggregateChildCountTooLarge { remaining: u32, child_count: u32 },

    #[error("round plan must include at least one proof stage")]
    EmptyRoundPlan,
}
