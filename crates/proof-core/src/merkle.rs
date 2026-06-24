use crate::error::{ProofError, ProofResult};
use crate::field::{pow5, Field};
use crate::hash_backend::{hash_quin, hash_quin_digests, hash_state_leaf};
use crate::native_types::{digest_to_field, field_to_digest, Digest};
use crate::packing::path_index_at;
use crate::types::PathElement;
use std::sync::{Mutex, OnceLock};

pub const QUIN_ARITY: usize = 5;
pub const QUIN_SIBLINGS: usize = QUIN_ARITY - 1;

static ZERO_ROOTS: OnceLock<Mutex<Vec<Field>>> = OnceLock::new();

pub fn hash5_exact(children: &[Field]) -> ProofResult<Field> {
    if children.len() != QUIN_ARITY {
        return Err(ProofError::InvalidLength {
            name: "quin hash children",
            expected: QUIN_ARITY,
            actual: children.len(),
        });
    }
    hash_quin(children)
}

pub fn hash5_digest(children: &[Digest; QUIN_ARITY]) -> Digest {
    hash_quin_digests(children)
}

pub fn hash10_exact(values: &[Field]) -> ProofResult<Field> {
    hash_state_leaf(values)
}

pub fn hash10_digest(values: &[Field]) -> ProofResult<Digest> {
    Ok(field_to_digest(&hash10_exact(values)?))
}

pub fn zero_root(depth: usize) -> ProofResult<Field> {
    let roots = ZERO_ROOTS.get_or_init(|| Mutex::new(vec![Field::from(0u32)]));
    let mut roots = roots
        .lock()
        .map_err(|_| ProofError::Crypto("zero root cache lock poisoned".to_string()))?;

    while roots.len() <= depth {
        let previous = roots
            .last()
            .expect("zero root cache is never empty")
            .clone();
        let children: [Field; QUIN_ARITY] = std::array::from_fn(|_| previous.clone());
        roots.push(hash5_exact(&children)?);
    }

    Ok(roots[depth].clone())
}

pub fn root_from_path(
    leaf: &Field,
    leaf_index: &Field,
    path_elements: &[PathElement],
) -> ProofResult<Field> {
    Ok(digest_to_field(root_from_path_digest(
        &field_to_digest(leaf),
        leaf_index,
        path_elements,
    )?))
}

pub fn root_from_path_digest(
    leaf: &Digest,
    leaf_index: &Field,
    path_elements: &[PathElement],
) -> ProofResult<Digest> {
    let mut current = *leaf;
    for (level, siblings) in path_elements.iter().enumerate() {
        let sibling_digests: [Digest; QUIN_SIBLINGS] =
            std::array::from_fn(|idx| field_to_digest(&siblings[idx]));
        let idx = path_index_at(leaf_index, level, QUIN_ARITY);
        let mut sibling_idx = 0;
        let children: [Digest; QUIN_ARITY] = std::array::from_fn(|child_idx| {
            if child_idx == idx {
                current
            } else {
                let sibling = sibling_digests[sibling_idx];
                sibling_idx += 1;
                sibling
            }
        });
        current = hash5_digest(&children);
    }
    Ok(current)
}

pub fn check_inclusion(
    name: &'static str,
    leaf: &Field,
    leaf_index: &Field,
    path_elements: &[PathElement],
    expected_root: &Field,
) -> ProofResult<()> {
    check_inclusion_digest(
        name,
        &field_to_digest(leaf),
        leaf_index,
        path_elements,
        &field_to_digest(expected_root),
    )
}

pub fn check_inclusion_digest(
    name: &'static str,
    leaf: &Digest,
    leaf_index: &Field,
    path_elements: &[PathElement],
    expected_root: &Digest,
) -> ProofResult<()> {
    let actual = root_from_path_digest(leaf, leaf_index, path_elements)?;
    if &actual == expected_root {
        Ok(())
    } else {
        Err(ProofError::MerkleRootMismatch {
            name,
            expected: digest_to_field(*expected_root),
            actual: digest_to_field(actual),
        })
    }
}

pub fn check_root(leaves: &[Field], levels: usize) -> ProofResult<Field> {
    let leaves: Vec<Digest> = leaves.iter().map(field_to_digest).collect();
    Ok(digest_to_field(check_root_digest(&leaves, levels)?))
}

pub fn check_root_digest(leaves: &[Digest], levels: usize) -> ProofResult<Digest> {
    let expected = pow5(QUIN_ARITY, levels);
    if leaves.len() != expected {
        return Err(ProofError::InvalidLength {
            name: "quin check root leaves",
            expected,
            actual: leaves.len(),
        });
    }

    let mut level: Vec<Digest> = leaves.to_vec();
    for _ in 0..levels {
        let mut next = Vec::with_capacity(level.len() / QUIN_ARITY);
        for chunk in level.chunks(QUIN_ARITY) {
            let children: [Digest; QUIN_ARITY] = chunk
                .try_into()
                .expect("validated quin tree level chunks have exact arity");
            next.push(hash5_digest(&children));
        }
        level = next;
    }
    Ok(level[0])
}

pub fn state_leaf_hash(row: &[Field]) -> ProofResult<Field> {
    hash10_exact(row)
}

pub fn state_leaf_hash_digest(row: &[Field]) -> ProofResult<Digest> {
    hash10_digest(row)
}
