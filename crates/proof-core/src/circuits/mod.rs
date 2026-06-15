pub mod add_new_key;
pub mod process_deactivate;
pub mod process_messages;
pub mod tally_votes;

use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use maci_crypto::{compute_input_hash, poseidon};

/// `HashLeftRight` use for coordinator public keys in AMACI input hashers.
pub(crate) fn coord_pub_key_hash(coord_pub_key: &[Field; 2]) -> Field {
    poseidon(coord_pub_key)
}

/// Mirrors `utils/hasherSha256.circom::Sha256Hasher` through `compute_input_hash`.
pub(crate) fn assert_input_hash(actual: &Field, values: &[Field]) -> ProofResult<()> {
    let expected = compute_input_hash(values);
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
    poseidon(&[left.clone(), right.clone()])
}

/// Mirrors `utils/hasherPoseidon.circom::Hasher13`.
pub(crate) fn hash13(elements: &[Field]) -> ProofResult<Field> {
    if elements.len() != 13 {
        return Err(ProofError::InvalidLength {
            name: "Hasher13",
            expected: 13,
            actual: elements.len(),
        });
    }
    let h1 = poseidon(&elements[0..5]);
    let h2 = poseidon(&elements[5..10]);
    Ok(poseidon(&[
        h1,
        h2,
        elements[10].clone(),
        elements[11].clone(),
        elements[12].clone(),
    ]))
}
