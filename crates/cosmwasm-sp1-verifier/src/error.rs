use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("SP1 Groth16 verification failed: {reason}")]
    Groth16Verification { reason: String },

    #[error("SP1 compressed verification failed: {reason}")]
    CompressedVerification { reason: String },
}
