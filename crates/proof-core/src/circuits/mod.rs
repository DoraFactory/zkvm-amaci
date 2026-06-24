pub mod add_new_key;
pub mod process_deactivate;
pub mod process_messages;
pub mod tally_votes;

use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::hash_backend::{hash_message_13, hash_pair, hash_public_inputs};

/// `HashLeftRight` use for coordinator public keys in AMACI input hashers.
pub(crate) fn coord_pub_key_hash(coord_pub_key: &[Field; 2]) -> Field {
    hash_pair(&coord_pub_key[0], &coord_pub_key[1])
}

/// Mirrors `utils/hasherSha256.circom::Sha256Hasher` through `compute_input_hash`.
pub(crate) fn assert_input_hash(actual: &Field, values: &[Field]) -> ProofResult<()> {
    let expected = hash_public_inputs(values);
    if &expected == actual {
        Ok(())
    } else {
        Err(ProofError::InputHashMismatch {
            expected,
            actual: actual.clone(),
        })
    }
}

pub(crate) fn poseidon2(left: &Field, right: &Field) -> Field {
    hash_pair(left, right)
}

/// Mirrors `utils/hasherPoseidon.circom::Hasher13`.
pub(crate) fn hash13(elements: &[Field]) -> ProofResult<Field> {
    hash_message_13(elements)
}
