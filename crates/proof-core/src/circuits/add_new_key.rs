use crate::circuits::{assert_input_hash, coord_pub_key_hash};
use crate::crypto::ecdh_formatted_priv_key;
use crate::error::{ProofError, ProofResult};
use crate::merkle::check_inclusion;
use crate::public_output::AddNewKeyPublicOutput;
use crate::types::AddNewKeyInput;
use maci_crypto::{poseidon, rerandomize_ciphertext, Ciphertext};
use num_bigint::BigUint;

/// Mirrors `amaci/power/addNewKey.circom::AddNewKey`.
pub fn execute(input: &AddNewKeyInput) -> ProofResult<AddNewKeyPublicOutput> {
    let expected_nullifier = poseidon(&[input.old_private_key.clone(), input.poll_id.clone()]);
    if expected_nullifier != input.nullifier {
        return Err(ProofError::CommitmentMismatch {
            name: "nullifier",
            expected: expected_nullifier,
            actual: input.nullifier.clone(),
        });
    }

    let shared_key = ecdh_formatted_priv_key(&input.old_private_key, &input.coord_pub_key);
    let shared_key_hash = poseidon(&shared_key);
    let expected_deactivate_leaf = poseidon(&[
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

    let rerandomized = rerandomize_ciphertext(
        &input.coord_pub_key,
        &Ciphertext {
            c1: input.c1.clone(),
            c2: input.c2.clone(),
            x_increment: BigUint::from(0u32),
        },
        Some(input.random_val.clone()),
    )?;
    if rerandomized.c1 != input.d1 {
        return Err(ProofError::CommitmentMismatch {
            name: "d1",
            expected: poseidon(&rerandomized.c1),
            actual: poseidon(&input.d1),
        });
    }
    if rerandomized.c2 != input.d2 {
        return Err(ProofError::CommitmentMismatch {
            name: "d2",
            expected: poseidon(&rerandomized.c2),
            actual: poseidon(&input.d2),
        });
    }

    let coord_hash = coord_pub_key_hash(&input.coord_pub_key);
    let new_pub_key_hash = poseidon(&input.new_pub_key);
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
        input_hash: input.input_hash.clone(),
        deactivate_root: input.deactivate_root.clone(),
        coord_pub_key_hash: coord_hash,
        nullifier: input.nullifier.clone(),
        d1: input.d1.clone(),
        d2: input.d2.clone(),
        new_pub_key_hash,
        poll_id: input.poll_id.clone(),
    })
}
