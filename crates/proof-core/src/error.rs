use crate::field::Field;
use thiserror::Error;

pub type ProofResult<T> = Result<T, ProofError>;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("input hash mismatch: expected {expected}, got {actual}")]
    InputHashMismatch { expected: Field, actual: Field },

    #[error("commitment mismatch for {name}: expected {expected}, got {actual}")]
    CommitmentMismatch {
        name: &'static str,
        expected: Field,
        actual: Field,
    },

    #[error("Merkle root mismatch for {name}: expected {expected}, got {actual}")]
    MerkleRootMismatch {
        name: &'static str,
        expected: Field,
        actual: Field,
    },

    #[error("message hash chain mismatch: expected {expected}, got {actual}")]
    MessageHashChainMismatch { expected: Field, actual: Field },

    #[error("invalid input length for {name}: expected {expected}, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid range for {name}: value {value} exceeds {max}")]
    InvalidRange {
        name: &'static str,
        value: Field,
        max: Field,
    },

    #[error("invalid boolean for {name}: {value}")]
    InvalidBoolean { name: &'static str, value: Field },

    #[error("arithmetic {operation} failed while computing {name}")]
    Arithmetic {
        operation: &'static str,
        name: &'static str,
    },

    #[error("native ciphertext authentication failed")]
    CiphertextAuthentication,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("codec error: {0}")]
    Codec(String),
}
