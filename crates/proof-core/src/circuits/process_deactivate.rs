use crate::circuits::process_messages::{message_chain, EmptyRule};
use crate::circuits::{assert_input_hash, coord_pub_key_hash, hash2};
use crate::crypto::{
    decrypt_deactivation_flag, ecdh_formatted_priv_key, private_to_pub_key,
    verify_command_signature,
};
use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::hash_backend::hash_fields;
use crate::merkle::{
    check_inclusion, check_inclusion_digest, root_from_path, state_leaf_hash_digest,
};
use crate::native_types::field_to_digest;
use crate::public_output::{public_value, ProcessDeactivatePublicOutput};
use crate::types::ProcessDeactivateInput;
use num_traits::One;

pub fn execute(input: &ProcessDeactivateInput) -> ProofResult<ProcessDeactivatePublicOutput> {
    if input.msgs.len() != input.batch_size {
        return Err(ProofError::InvalidLength {
            name: "deactivate msgs",
            expected: input.batch_size,
            actual: input.msgs.len(),
        });
    }
    if input.enc_pub_keys.len() != input.batch_size {
        return Err(ProofError::InvalidLength {
            name: "deactivate encPubKeys",
            expected: input.batch_size,
            actual: input.enc_pub_keys.len(),
        });
    }
    validate_batch_witness_lengths(input)?;

    let current = hash2(
        &input.current_active_state_root,
        &input.current_deactivate_root,
    );
    if current != input.current_deactivate_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "currentDeactivateCommitment",
            expected: current,
            actual: input.current_deactivate_commitment.clone(),
        });
    }

    let derived = private_to_pub_key(&input.coord_priv_key);
    if derived != input.coord_pub_key {
        return Err(ProofError::CommitmentMismatch {
            name: "coordPubKey",
            expected: hash2(&derived[0], &derived[1]),
            actual: hash2(&input.coord_pub_key[0], &input.coord_pub_key[1]),
        });
    }

    let chain_end = message_chain(
        &input.batch_start_hash,
        &input.msgs,
        &input.enc_pub_keys,
        EmptyRule::Message0,
    )?;
    if chain_end != input.batch_end_hash {
        return Err(ProofError::MessageHashChainMismatch {
            expected: input.batch_end_hash.clone(),
            actual: chain_end,
        });
    }

    let coord_hash = coord_pub_key_hash(&input.coord_pub_key);
    assert_input_hash(
        &input.input_hash,
        &[
            input.new_deactivate_root.clone(),
            coord_hash.clone(),
            input.batch_start_hash.clone(),
            input.batch_end_hash.clone(),
            input.current_deactivate_commitment.clone(),
            input.new_deactivate_commitment.clone(),
            input.current_state_root.clone(),
            input.expected_poll_id.clone(),
        ],
    )?;

    let (active_root, deactivate_root) = process_batch(input)?;
    if deactivate_root != input.new_deactivate_root {
        return Err(ProofError::MerkleRootMismatch {
            name: "newDeactivateRoot",
            expected: input.new_deactivate_root.clone(),
            actual: deactivate_root,
        });
    }
    let expected_new_commitment = hash2(&active_root, &input.new_deactivate_root);
    if expected_new_commitment != input.new_deactivate_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "newDeactivateCommitment",
            expected: expected_new_commitment,
            actual: input.new_deactivate_commitment.clone(),
        });
    }

    Ok(ProcessDeactivatePublicOutput {
        input_hash: public_value(&input.input_hash),
        new_deactivate_root: public_value(&input.new_deactivate_root),
        coord_pub_key_hash: public_value(&coord_hash),
        batch_start_hash: public_value(&input.batch_start_hash),
        batch_end_hash: public_value(&input.batch_end_hash),
        current_deactivate_commitment: public_value(&input.current_deactivate_commitment),
        new_deactivate_commitment: public_value(&input.new_deactivate_commitment),
        current_state_root: public_value(&input.current_state_root),
        expected_poll_id: public_value(&input.expected_poll_id),
    })
}

fn validate_batch_witness_lengths(input: &ProcessDeactivateInput) -> ProofResult<()> {
    for (name, actual) in [
        ("c1", input.c1.len()),
        ("c2", input.c2.len()),
        ("currentActiveState", input.current_active_state.len()),
        ("newActiveState", input.new_active_state.len()),
        ("currentStateLeaves", input.current_state_leaves.len()),
        (
            "currentStateLeavesPathElements",
            input.current_state_leaves_path_elements.len(),
        ),
        (
            "activeStateLeavesPathElements",
            input.active_state_leaves_path_elements.len(),
        ),
        (
            "deactivateLeavesPathElements",
            input.deactivate_leaves_path_elements.len(),
        ),
    ] {
        if actual != input.batch_size {
            return Err(ProofError::InvalidLength {
                name,
                expected: input.batch_size,
                actual,
            });
        }
    }
    Ok(())
}

fn process_batch(input: &ProcessDeactivateInput) -> ProofResult<(Field, Field)> {
    let mut active_root = input.current_active_state_root.clone();
    let mut deactivate_root = input.current_deactivate_root.clone();

    for i in 0..input.batch_size {
        let is_empty = input.msgs[i][0].is_zero();
        if is_empty {
            continue;
        }
        let command = decrypt_deactivate_command(input, i)?;
        let roots = process_one(input, i, &active_root, &deactivate_root, &command)?;
        active_root = roots.0;
        deactivate_root = roots.1;
    }

    Ok((active_root, deactivate_root))
}

#[derive(Debug, Clone)]
struct DeactivateCommand {
    state_index: Field,
    poll_id: Field,
    sig_r8: [Field; 2],
    sig_s: Field,
    packed_command: [Field; 3],
}

fn decrypt_deactivate_command(
    input: &ProcessDeactivateInput,
    i: usize,
) -> ProofResult<DeactivateCommand> {
    let cmd = crate::circuits::process_messages::message_to_command(
        &input.msgs[i],
        &input.coord_priv_key,
        &input.enc_pub_keys[i],
    )?;
    Ok(DeactivateCommand {
        state_index: cmd.state_index,
        poll_id: cmd.poll_id,
        sig_r8: cmd.sig_r8,
        sig_s: cmd.sig_s,
        packed_command: cmd.packed_command,
    })
}

fn process_one(
    input: &ProcessDeactivateInput,
    i: usize,
    current_active_state_root: &Field,
    current_deactivate_root: &Field,
    command: &DeactivateCommand,
) -> ProofResult<(Field, Field)> {
    let state_leaf = &input.current_state_leaves[i];
    let poll_ok = command.poll_id == input.expected_poll_id;
    let sig_ok = if poll_ok {
        verify_command_signature(
            &[state_leaf[0].clone(), state_leaf[1].clone()],
            &command.sig_r8,
            &command.sig_s,
            &command.packed_command,
        )?
    } else {
        false
    };
    let current_is_odd = if sig_ok && poll_ok {
        decrypt_deactivation_flag(
            &[state_leaf[5].clone(), state_leaf[6].clone()],
            &[state_leaf[7].clone(), state_leaf[8].clone()],
            &input.coord_priv_key,
        )?
        .1
    } else {
        true
    };
    let valid = sig_ok && !current_is_odd && poll_ok;

    let max_index = Field::from(5usize.pow(input.state_tree_depth as u32));
    let index_for_state = if command.state_index <= max_index {
        command.state_index.clone()
    } else {
        &max_index - Field::one()
    };
    let state_hash = state_leaf_hash_digest(state_leaf)?;
    check_inclusion_digest(
        "deactivate state leaf",
        &state_hash,
        &index_for_state,
        &input.current_state_leaves_path_elements[i],
        &field_to_digest(&input.current_state_root),
    )?;

    let new_status_is_odd =
        decrypt_deactivation_flag(&input.c1[i], &input.c2[i], &input.coord_priv_key)?.1;
    if valid != !new_status_is_odd {
        return Err(ProofError::CommitmentMismatch {
            name: "deactivate status parity",
            expected: Field::from(valid as u32),
            actual: Field::from((!new_status_is_odd) as u32),
        });
    }

    if input.new_active_state[i].is_zero() {
        return Err(ProofError::InvalidRange {
            name: "newActiveState",
            value: input.new_active_state[i].clone(),
            max: Field::from(0u32),
        });
    }

    check_inclusion(
        "current active state",
        &input.current_active_state[i],
        &index_for_state,
        &input.active_state_leaves_path_elements[i],
        current_active_state_root,
    )?;
    let active_leaf = if valid {
        input.new_active_state[i].clone()
    } else {
        input.current_active_state[i].clone()
    };
    let new_active_root = root_from_path(
        &active_leaf,
        &index_for_state,
        &input.active_state_leaves_path_elements[i],
    )?;

    let deactivate_index = &input.deactivate_index0 + Field::from(i);
    check_inclusion(
        "current deactivate zero leaf",
        &Field::from(0u32),
        &deactivate_index,
        &input.deactivate_leaves_path_elements[i],
        current_deactivate_root,
    )?;

    let shared_key = ecdh_formatted_priv_key(
        &input.coord_priv_key,
        &[state_leaf[0].clone(), state_leaf[1].clone()],
    );
    let shared_key_hash = hash_fields(&shared_key);
    let deactivate_leaf_hash = hash_fields(&[
        input.c1[i][0].clone(),
        input.c1[i][1].clone(),
        input.c2[i][0].clone(),
        input.c2[i][1].clone(),
        shared_key_hash,
    ]);
    let new_deactivate_leaf = deactivate_leaf_hash;
    let new_deactivate_root = root_from_path(
        &new_deactivate_leaf,
        &deactivate_index,
        &input.deactivate_leaves_path_elements[i],
    )?;

    Ok((new_active_root, new_deactivate_root))
}
