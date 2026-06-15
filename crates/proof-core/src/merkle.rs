use crate::error::{ProofError, ProofResult};
use crate::field::{pow5, Field};
use crate::packing::path_index_at;
use maci_crypto::{hash10, hash5};
use num_bigint::BigUint;

pub const QUIN_ARITY: usize = 5;
pub const QUIN_SIBLINGS: usize = QUIN_ARITY - 1;

pub fn hash5_exact(children: &[Field]) -> ProofResult<Field> {
    if children.len() != QUIN_ARITY {
        return Err(ProofError::InvalidLength {
            name: "quin hash children",
            expected: QUIN_ARITY,
            actual: children.len(),
        });
    }
    Ok(hash5(children)?)
}

pub fn hash10_exact(values: &[Field]) -> ProofResult<Field> {
    if values.len() != 10 {
        return Err(ProofError::InvalidLength {
            name: "state leaf",
            expected: 10,
            actual: values.len(),
        });
    }
    Ok(hash10(values)?)
}

/// Mirrors `utils/trees/zeroRoot.circom::ZeroRoot`.
pub fn zero_root(depth: usize) -> ProofResult<Field> {
    let mut current = BigUint::from(0u32);
    for _ in 0..depth {
        current = hash5_exact(&vec![current; QUIN_ARITY])?;
    }
    Ok(current)
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
        let mut children = Vec::with_capacity(QUIN_ARITY);
        let mut sibling_idx = 0;
        for child_idx in 0..QUIN_ARITY {
            if child_idx == idx {
                children.push(current.clone());
            } else {
                children.push(siblings[sibling_idx].clone());
                sibling_idx += 1;
            }
        }
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
