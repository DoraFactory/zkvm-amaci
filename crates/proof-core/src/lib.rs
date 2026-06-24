//! zkVM-independent AMACI proof logic core.
//!
//! This crate intentionally has no RISC Zero or SP1 dependency. Guest programs
//! should only deserialize [`ProverInput`], call [`execute_proof_logic`], and
//! commit the returned [`PublicOutput`].

pub mod circuits;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod execute;
pub mod field;
pub mod hash_backend;
pub mod merkle;
pub mod native_types;
pub mod packing;
pub mod public_output;
pub mod sample_inputs;
pub mod types;

pub use error::{ProofError, ProofResult};
pub use execute::execute_proof_logic;
pub use field::Field;
pub use public_output::*;
pub use types::*;
