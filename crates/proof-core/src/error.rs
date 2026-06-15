use num_bigint::BigUint;
use thiserror::Error;

pub type ProofResult<T> = Result<T, ProofError>;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("input hash mismatch: expected {expected}, got {actual}")]
    InputHashMismatch { expected: BigUint, actual: BigUint },

    #[error("commitment mismatch for {name}: expected {expected}, got {actual}")]
    CommitmentMismatch {
        name: &'static str,
        expected: BigUint,
        actual: BigUint,
    },

    #[error("Merkle root mismatch for {name}: expected {expected}, got {actual}")]
    MerkleRootMismatch {
        name: &'static str,
        expected: BigUint,
        actual: BigUint,
    },

    #[error("message hash chain mismatch: expected {expected}, got {actual}")]
    MessageHashChainMismatch { expected: BigUint, actual: BigUint },

    #[error("invalid input length for {name}: expected {expected}, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid range for {name}: value {value} exceeds {max}")]
    InvalidRange {
        name: &'static str,
        value: BigUint,
        max: BigUint,
    },

    #[error("invalid boolean for {name}: {value}")]
    InvalidBoolean { name: &'static str, value: BigUint },

    #[error("unsupported migration step: {0}")]
    Unsupported(&'static str),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<maci_crypto::CryptoError> for ProofError {
    fn from(value: maci_crypto::CryptoError) -> Self {
        Self::Crypto(value.to_string())
    }
}
