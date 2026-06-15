use crate::circuits::process_messages::{message_chain, EmptyRule};
use crate::circuits::{assert_input_hash, coord_pub_key_hash, poseidon2};
use crate::crypto::{
    ecdh_formatted_priv_key, elgamal_decrypt_x_and_odd, private_to_pub_key,
    verify_command_signature,
};
use crate::error::{ProofError, ProofResult};
use crate::merkle::{check_inclusion, root_from_path, state_leaf_hash};
use crate::public_output::ProcessDeactivatePublicOutput;
use crate::types::ProcessDeactivateInput;
use maci_crypto::poseidon;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Mirrors `amaci/power/processDeactivate.circom::ProcessDeactivateMessages`.
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

    let current = poseidon2(
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
            expected: poseidon2(&derived[0], &derived[1]),
            actual: poseidon2(&input.coord_pub_key[0], &input.coord_pub_key[1]),
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
    let expected_new_commitment = poseidon2(&active_root, &input.new_deactivate_root);
    if expected_new_commitment != input.new_deactivate_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "newDeactivateCommitment",
            expected: expected_new_commitment,
            actual: input.new_deactivate_commitment.clone(),
        });
    }

    Ok(ProcessDeactivatePublicOutput {
        input_hash: input.input_hash.clone(),
        new_deactivate_root: input.new_deactivate_root.clone(),
        coord_pub_key_hash: coord_hash,
        batch_start_hash: input.batch_start_hash.clone(),
        batch_end_hash: input.batch_end_hash.clone(),
        current_deactivate_commitment: input.current_deactivate_commitment.clone(),
        new_deactivate_commitment: input.new_deactivate_commitment.clone(),
        current_state_root: input.current_state_root.clone(),
        expected_poll_id: input.expected_poll_id.clone(),
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

fn process_batch(input: &ProcessDeactivateInput) -> ProofResult<(BigUint, BigUint)> {
    let mut active_root = input.current_active_state_root.clone();
    let mut deactivate_root = input.current_deactivate_root.clone();
    let deactivate_tree_depth = input.state_tree_depth + 2;

    for i in 0..input.batch_size {
        let is_empty = input.msgs[i][0].is_zero();
        let command = if is_empty {
            DeactivateCommand::empty(
                &(BigUint::from(5usize.pow(input.state_tree_depth as u32)) - BigUint::one()),
            )
        } else {
            decrypt_deactivate_command(input, i)?
        };
        let roots = process_one(
            input,
            i,
            deactivate_tree_depth,
            &active_root,
            &deactivate_root,
            &command,
            is_empty,
        )?;
        active_root = roots.0;
        deactivate_root = roots.1;
    }

    Ok((active_root, deactivate_root))
}

#[derive(Debug, Clone)]
struct DeactivateCommand {
    state_index: BigUint,
    poll_id: BigUint,
    sig_r8: [BigUint; 2],
    sig_s: BigUint,
    packed_command: [BigUint; 3],
}

impl DeactivateCommand {
    fn empty(state_index: &BigUint) -> Self {
        Self {
            state_index: state_index.clone(),
            poll_id: BigUint::from(0u32),
            sig_r8: [BigUint::from(0u32), BigUint::from(0u32)],
            sig_s: BigUint::from(0u32),
            packed_command: [
                BigUint::from(0u32),
                BigUint::from(0u32),
                BigUint::from(0u32),
            ],
        }
    }
}

/// Reuses `utils/messageToCommand.circom::MessageToCommand` for deactivate commands.
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

/// Mirrors one forward iteration of `ProcessDeactivateMessages`.
fn process_one(
    input: &ProcessDeactivateInput,
    i: usize,
    deactivate_tree_depth: usize,
    current_active_state_root: &BigUint,
    current_deactivate_root: &BigUint,
    command: &DeactivateCommand,
    is_empty: bool,
) -> ProofResult<(BigUint, BigUint)> {
    let state_leaf = &input.current_state_leaves[i];
    if state_leaf.len() != 10 {
        return Err(ProofError::InvalidLength {
            name: "deactivate state leaf",
            expected: 10,
            actual: state_leaf.len(),
        });
    }

    let poll_ok = command.poll_id == input.expected_poll_id;
    let sig_ok = if !is_empty && poll_ok {
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
        elgamal_decrypt_x_and_odd(
            &[state_leaf[5].clone(), state_leaf[6].clone()],
            &[state_leaf[7].clone(), state_leaf[8].clone()],
            &input.coord_priv_key,
        )?
        .1
    } else {
        true
    };
    let valid = sig_ok && !current_is_odd && poll_ok;

    let max_index = BigUint::from(5usize.pow(input.state_tree_depth as u32));
    let index_for_state = if command.state_index <= max_index {
        command.state_index.clone()
    } else {
        &max_index - BigUint::one()
    };
    let state_hash = state_leaf_hash(state_leaf)?;
    check_inclusion(
        "deactivate state leaf",
        &state_hash,
        &index_for_state,
        &input.current_state_leaves_path_elements[i],
        &input.current_state_root,
    )?;

    let new_status_is_odd =
        elgamal_decrypt_x_and_odd(&input.c1[i], &input.c2[i], &input.coord_priv_key)?.1;
    if valid != !new_status_is_odd {
        return Err(ProofError::CommitmentMismatch {
            name: "deactivate status parity",
            expected: BigUint::from(valid as u32),
            actual: BigUint::from((!new_status_is_odd) as u32),
        });
    }

    if input.new_active_state[i].is_zero() {
        return Err(ProofError::InvalidRange {
            name: "newActiveState",
            value: input.new_active_state[i].clone(),
            max: BigUint::from(0u32),
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

    let deactivate_index = &input.deactivate_index0 + BigUint::from(i);
    check_inclusion(
        "current deactivate zero leaf",
        &BigUint::from(0u32),
        &deactivate_index,
        &input.deactivate_leaves_path_elements[i],
        current_deactivate_root,
    )?;

    let shared_key = ecdh_formatted_priv_key(
        &input.coord_priv_key,
        &[state_leaf[0].clone(), state_leaf[1].clone()],
    );
    let shared_key_hash = poseidon(&shared_key);
    let deactivate_leaf_hash = poseidon(&[
        input.c1[i][0].clone(),
        input.c1[i][1].clone(),
        input.c2[i][0].clone(),
        input.c2[i][1].clone(),
        shared_key_hash,
    ]);
    let new_deactivate_leaf = if is_empty {
        BigUint::from(0u32)
    } else {
        deactivate_leaf_hash
    };
    let new_deactivate_root = root_from_path(
        &new_deactivate_leaf,
        &deactivate_index,
        &input.deactivate_leaves_path_elements[i],
    )?;

    let _ = deactivate_tree_depth;
    Ok((new_active_root, new_deactivate_root))
}
