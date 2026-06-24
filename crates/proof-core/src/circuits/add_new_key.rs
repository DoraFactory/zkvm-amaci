use crate::circuits::{assert_input_hash, coord_pub_key_hash};
use crate::crypto::{ecdh_formatted_priv_key, native_rerandomize_ciphertext};
use crate::error::{ProofError, ProofResult};
use crate::hash_backend::{hash_fields, hash_pair};
use crate::merkle::check_inclusion;
use crate::public_output::{public_value, AddNewKeyPublicOutput};
use crate::types::AddNewKeyInput;

pub fn execute(input: &AddNewKeyInput) -> ProofResult<AddNewKeyPublicOutput> {
    let expected_nullifier = hash_pair(&input.old_private_key, &input.poll_id);
    if expected_nullifier != input.nullifier {
        return Err(ProofError::CommitmentMismatch {
            name: "nullifier",
            expected: expected_nullifier,
            actual: input.nullifier.clone(),
        });
    }

    let shared_key = ecdh_formatted_priv_key(&input.old_private_key, &input.coord_pub_key);
    let shared_key_hash = hash_fields(&shared_key);
    let expected_deactivate_leaf = hash_fields(&[
        input.c1[0].clone(),
        input.c1[1].clone(),
        input.c2[0].clone(),
        input.c2[1].clone(),
        shared_key_hash,
    ]);
    if expected_deactivate_leaf != input.deactivate_leaf {
        return Err(ProofError::CommitmentMismatch {
            name: "deactivateLeaf",
            expected: expected_deactivate_leaf,
            actual: input.deactivate_leaf.clone(),
        });
    }

    check_inclusion(
        "deactivate leaf",
        &input.deactivate_leaf,
        &input.deactivate_index,
        &input.deactivate_leaf_path_elements,
        &input.deactivate_root,
    )?;

    let (expected_d1, expected_d2) = native_rerandomize_ciphertext(
        &input.coord_pub_key,
        &input.c1,
        &input.c2,
        &input.random_val,
    );
    if expected_d1 != input.d1 {
        return Err(ProofError::CommitmentMismatch {
            name: "d1",
            expected: hash_fields(&expected_d1),
            actual: hash_fields(&input.d1),
        });
    }
    if expected_d2 != input.d2 {
        return Err(ProofError::CommitmentMismatch {
            name: "d2",
            expected: hash_fields(&expected_d2),
            actual: hash_fields(&input.d2),
        });
    }

    let coord_hash = coord_pub_key_hash(&input.coord_pub_key);
    let new_pub_key_hash = hash_fields(&input.new_pub_key);
    assert_input_hash(
        &input.input_hash,
        &[
            input.deactivate_root.clone(),
            coord_hash.clone(),
            input.nullifier.clone(),
            input.d1[0].clone(),
            input.d1[1].clone(),
            input.d2[0].clone(),
            input.d2[1].clone(),
            new_pub_key_hash.clone(),
            input.poll_id.clone(),
        ],
    )?;

    Ok(AddNewKeyPublicOutput {
        input_hash: public_value(&input.input_hash),
        deactivate_root: public_value(&input.deactivate_root),
        coord_pub_key_hash: public_value(&coord_hash),
        nullifier: public_value(&input.nullifier),
        d1: [public_value(&input.d1[0]), public_value(&input.d1[1])],
        d2: [public_value(&input.d2[0]), public_value(&input.d2[1])],
        new_pub_key_hash: public_value(&new_pub_key_hash),
        poll_id: public_value(&input.poll_id),
    })
}
