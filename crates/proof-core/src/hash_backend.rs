use crate::error::{ProofError, ProofResult};
use crate::field::Field;
#[cfg(not(feature = "zkvm-native-crypto"))]
use maci_crypto::{compute_input_hash, hash10, hash5, poseidon};
#[cfg(feature = "zkvm-native-crypto")]
use num_bigint::BigUint;
#[cfg(feature = "zkvm-native-crypto")]
use sha2::{Digest, Sha256};

#[cfg(feature = "zkvm-native-crypto")]
const NATIVE_HASH_DOMAIN: &[u8] = b"AMACI_ZKVM_NATIVE_HASH_V1";
#[cfg(feature = "zkvm-native-crypto")]
const NATIVE_INPUT_DOMAIN: &[u8] = b"AMACI_ZKVM_NATIVE_INPUT_V1";

pub fn hash_fields(elements: &[Field]) -> Field {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        sha256_field_hash(NATIVE_HASH_DOMAIN, elements)
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        poseidon(elements)
    }
}

pub fn hash_pair(left: &Field, right: &Field) -> Field {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        sha256_field_hash_refs(NATIVE_HASH_DOMAIN, &[left, right])
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        maci_crypto::hash_left_right(left, right)
    }
}

pub fn hash_public_inputs(values: &[Field]) -> Field {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        sha256_field_hash(NATIVE_INPUT_DOMAIN, values)
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        compute_input_hash(values)
    }
}

pub fn hash_quin(children: &[Field]) -> ProofResult<Field> {
    if children.len() != 5 {
        return Err(ProofError::InvalidLength {
            name: "quin hash children",
            expected: 5,
            actual: children.len(),
        });
    }

    #[cfg(feature = "zkvm-native-crypto")]
    {
        Ok(sha256_field_hash(NATIVE_HASH_DOMAIN, children))
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        Ok(hash5(children)?)
    }
}

pub fn hash_state_leaf(row: &[Field]) -> ProofResult<Field> {
    if row.len() != 10 {
        return Err(ProofError::InvalidLength {
            name: "state leaf",
            expected: 10,
            actual: row.len(),
        });
    }

    #[cfg(feature = "zkvm-native-crypto")]
    {
        Ok(sha256_field_hash(NATIVE_HASH_DOMAIN, row))
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        Ok(hash10(row)?)
    }
}

pub fn hash_message_13(elements: &[Field]) -> ProofResult<Field> {
    if elements.len() != 13 {
        return Err(ProofError::InvalidLength {
            name: "Hasher13",
            expected: 13,
            actual: elements.len(),
        });
    }

    #[cfg(feature = "zkvm-native-crypto")]
    {
        Ok(sha256_field_hash(NATIVE_HASH_DOMAIN, elements))
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        let h1 = hash5(&elements[0..5])?;
        let h2 = hash5(&elements[5..10])?;
        Ok(hash5(&[
            h1,
            h2,
            elements[10].clone(),
            elements[11].clone(),
            elements[12].clone(),
        ])?)
    }
}

#[cfg(feature = "zkvm-native-crypto")]
fn sha256_field_hash(domain: &[u8], elements: &[Field]) -> Field {
    sha256_field_hash_iter(domain, elements.len(), elements.iter())
}

#[cfg(feature = "zkvm-native-crypto")]
fn sha256_field_hash_refs(domain: &[u8], elements: &[&Field]) -> Field {
    sha256_field_hash_iter(domain, elements.len(), elements.iter().copied())
}

#[cfg(feature = "zkvm-native-crypto")]
fn sha256_field_hash_iter<'a>(
    domain: &[u8],
    len: usize,
    elements: impl IntoIterator<Item = &'a Field>,
) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((len as u64).to_be_bytes());
    for element in elements {
        hasher.update(uint256_be(element));
    }
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest)
}

#[cfg(feature = "zkvm-native-crypto")]
fn uint256_be(value: &Field) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut word = [0u8; 32];
    if bytes.len() >= 32 {
        word.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        word[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    word
}
