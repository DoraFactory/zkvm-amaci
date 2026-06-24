use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::native_types::{digest_to_field, field_to_digest, Digest};
use sha2::{Digest as Sha2Digest, Sha256};

const NATIVE_HASH_DOMAIN: &[u8] = b"AMACI_ZKVM_NATIVE_HASH_V1";
const NATIVE_INPUT_DOMAIN: &[u8] = b"AMACI_ZKVM_NATIVE_INPUT_V1";

pub fn hash_fields(elements: &[Field]) -> Field {
    sha256_field_hash(NATIVE_HASH_DOMAIN, elements)
}

pub fn hash_pair(left: &Field, right: &Field) -> Field {
    sha256_field_hash_refs(NATIVE_HASH_DOMAIN, &[left, right])
}

pub fn hash_public_inputs(values: &[Field]) -> Field {
    sha256_field_hash(NATIVE_INPUT_DOMAIN, values)
}

pub fn hash_quin(children: &[Field]) -> ProofResult<Field> {
    if children.len() != 5 {
        return Err(ProofError::InvalidLength {
            name: "quin hash children",
            expected: 5,
            actual: children.len(),
        });
    }
    Ok(sha256_field_hash(NATIVE_HASH_DOMAIN, children))
}

pub fn hash_state_leaf(row: &[Field]) -> ProofResult<Field> {
    if row.len() != 10 {
        return Err(ProofError::InvalidLength {
            name: "state leaf",
            expected: 10,
            actual: row.len(),
        });
    }
    Ok(sha256_field_hash(NATIVE_HASH_DOMAIN, row))
}

pub fn hash_message_13(elements: &[Field]) -> ProofResult<Field> {
    if elements.len() != 13 {
        return Err(ProofError::InvalidLength {
            name: "Hasher13",
            expected: 13,
            actual: elements.len(),
        });
    }
    Ok(sha256_field_hash(NATIVE_HASH_DOMAIN, elements))
}

fn sha256_field_hash(domain: &[u8], elements: &[Field]) -> Field {
    sha256_field_hash_iter(domain, elements.len(), elements.iter())
}

fn sha256_field_hash_refs(domain: &[u8], elements: &[&Field]) -> Field {
    sha256_field_hash_iter(domain, elements.len(), elements.iter().copied())
}

fn sha256_field_hash_iter<'a>(
    domain: &[u8],
    len: usize,
    elements: impl IntoIterator<Item = &'a Field>,
) -> Field {
    digest_to_field(sha256_field_hash_iter_digest(domain, len, elements))
}

pub(crate) fn sha256_field_hash_iter_digest<'a>(
    domain: &[u8],
    len: usize,
    elements: impl IntoIterator<Item = &'a Field>,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((len as u64).to_be_bytes());
    for element in elements {
        hasher.update(field_to_digest(element));
    }
    hasher.finalize().into()
}

pub(crate) fn hash_quin_digests(children: &[Digest; 5]) -> Digest {
    sha256_digest_hash(NATIVE_HASH_DOMAIN, children)
}

fn sha256_digest_hash(domain: &[u8], elements: &[Digest]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((elements.len() as u64).to_be_bytes());
    for element in elements {
        hasher.update(element);
    }
    hasher.finalize().into()
}
