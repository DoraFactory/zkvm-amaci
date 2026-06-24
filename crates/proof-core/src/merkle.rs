use crate::error::{ProofError, ProofResult};
use crate::field::{pow5, Field};
use crate::hash_backend::{hash_quin, hash_state_leaf};
use crate::packing::path_index_at;
use num_bigint::BigUint;
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

pub fn hash10_exact(values: &[Field]) -> ProofResult<Field> {
    hash_state_leaf(values)
}

/// Mirrors `utils/trees/zeroRoot.circom::ZeroRoot`.
pub fn zero_root(depth: usize) -> ProofResult<Field> {
    let roots = ZERO_ROOTS.get_or_init(|| Mutex::new(vec![BigUint::from(0u32)]));
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

/// Mirrors `utils/trees/incrementalQuinTree.circom::QuinTreeInclusionProof`.
pub fn root_from_path(
    leaf: &Field,
    leaf_index: &Field,
    path_elements: &[Vec<Field>],
) -> ProofResult<Field> {
    let mut current = leaf.clone();
    for (level, siblings) in path_elements.iter().enumerate() {
        if siblings.len() != QUIN_SIBLINGS {
            return Err(ProofError::InvalidLength {
                name: "quin path siblings",
                expected: QUIN_SIBLINGS,
                actual: siblings.len(),
            });
        }
        let idx = path_index_at(leaf_index, level, QUIN_ARITY);
        let mut sibling_idx = 0;
        let children: [Field; QUIN_ARITY] = std::array::from_fn(|child_idx| {
            if child_idx == idx {
                current.clone()
            } else {
                let sibling = siblings[sibling_idx].clone();
                sibling_idx += 1;
                sibling
            }
        });
        current = hash5_exact(&children)?;
    }
    Ok(current)
}

pub fn check_inclusion(
    name: &'static str,
    leaf: &Field,
    leaf_index: &Field,
    path_elements: &[Vec<Field>],
    expected_root: &Field,
) -> ProofResult<()> {
    let actual = root_from_path(leaf, leaf_index, path_elements)?;
    if &actual == expected_root {
        Ok(())
    } else {
        Err(ProofError::MerkleRootMismatch {
            name,
            expected: expected_root.clone(),
            actual,
        })
    }
}

/// Mirrors `utils/trees/checkRoot.circom::QuinCheckRoot`.
pub fn check_root(leaves: &[Field], levels: usize) -> ProofResult<Field> {
    let expected = pow5(QUIN_ARITY, levels);
    if leaves.len() != expected {
        return Err(ProofError::InvalidLength {
            name: "quin check root leaves",
            expected,
            actual: leaves.len(),
        });
    }

    let mut level = leaves.to_vec();
    for _ in 0..levels {
        let mut next = Vec::with_capacity(level.len() / QUIN_ARITY);
        for chunk in level.chunks(QUIN_ARITY) {
            next.push(hash5_exact(chunk)?);
        }
        level = next;
    }
    Ok(level[0].clone())
}

/// Mirrors the AMACI 10-field state leaf hasher.
pub fn state_leaf_hash(row: &[Field]) -> ProofResult<Field> {
    hash10_exact(row)
}
