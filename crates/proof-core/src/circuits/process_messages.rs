use crate::circuits::{assert_input_hash, coord_pub_key_hash, hash13, hash2};
use crate::crypto::{
    decrypt_deactivation_flag, decrypt_without_check, ecdh_formatted_priv_key, private_to_pub_key,
    verify_command_signature,
};
use crate::error::{ProofError, ProofResult};
use crate::field::{ensure_bool, pow5, Field};
use crate::merkle::{
    check_inclusion, check_inclusion_digest, root_from_path, state_leaf_hash,
    state_leaf_hash_digest, zero_root,
};
use crate::native_types::field_to_digest;
use crate::packing::{
    decode_vote_weight_96, unpack_element_high_to_low, unpack_process_messages_packed_vals,
};
use crate::public_output::{public_value, ProcessMessagesPublicOutput};
use crate::types::{Message, ProcessMessagesInput, StateLeaf};
use num_traits::One;
use std::sync::OnceLock;

static MAX_VOTE_WEIGHT: OnceLock<Field> = OnceLock::new();

fn max_vote_weight() -> &'static Field {
    MAX_VOTE_WEIGHT.get_or_init(|| {
        Field::from_str_radix("147946756881789319005730692170996259609", 10).unwrap()
    })
}

pub fn execute(input: &ProcessMessagesInput) -> ProofResult<ProcessMessagesPublicOutput> {
    if input.msgs.len() != input.batch_size {
        return Err(ProofError::InvalidLength {
            name: "msgs",
            expected: input.batch_size,
            actual: input.msgs.len(),
        });
    }
    if input.enc_pub_keys.len() != input.batch_size {
        return Err(ProofError::InvalidLength {
            name: "encPubKeys",
            expected: input.batch_size,
            actual: input.enc_pub_keys.len(),
        });
    }
    validate_batch_witness_lengths(input)?;

    let packed = unpack_process_messages_packed_vals(&input.packed_vals)?;
    ensure_bool("isQuadraticCost", &packed.is_quadratic_cost)?;

    let max_vote_options = Field::from(pow5(5, input.vote_option_tree_depth));
    if packed.max_vote_options > max_vote_options {
        return Err(ProofError::InvalidRange {
            name: "maxVoteOptions",
            value: packed.max_vote_options,
            max: Field::from(pow5(5, input.vote_option_tree_depth)),
        });
    }
    let max_signups = Field::from(pow5(5, input.state_tree_depth));
    if packed.num_sign_ups > max_signups {
        return Err(ProofError::InvalidRange {
            name: "numSignUps",
            value: packed.num_sign_ups,
            max: Field::from(pow5(5, input.state_tree_depth)),
        });
    }

    let current_state_commitment = hash2(&input.current_state_root, &input.current_state_salt);
    if current_state_commitment != input.current_state_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "currentStateCommitment",
            expected: current_state_commitment,
            actual: input.current_state_commitment.clone(),
        });
    }

    let deactivate_commitment = hash2(&input.active_state_root, &input.deactivate_root);
    if deactivate_commitment != input.deactivate_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "deactivateCommitment",
            expected: deactivate_commitment,
            actual: input.deactivate_commitment.clone(),
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
        EmptyRule::EncPubKeyX,
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
            input.packed_vals.clone(),
            coord_hash.clone(),
            input.batch_start_hash.clone(),
            input.batch_end_hash.clone(),
            input.current_state_commitment.clone(),
            input.new_state_commitment.clone(),
            input.deactivate_commitment.clone(),
            input.expected_poll_id.clone(),
        ],
    )?;

    let computed_new_root = process_batch(input, &packed)?;
    let expected_new_commitment = hash2(&computed_new_root, &input.new_state_salt);
    if expected_new_commitment != input.new_state_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "newStateCommitment",
            expected: expected_new_commitment,
            actual: input.new_state_commitment.clone(),
        });
    }

    Ok(ProcessMessagesPublicOutput {
        input_hash: public_value(&input.input_hash),
        packed_vals: public_value(&input.packed_vals),
        coord_pub_key_hash: public_value(&coord_hash),
        batch_start_hash: public_value(&input.batch_start_hash),
        batch_end_hash: public_value(&input.batch_end_hash),
        current_state_commitment: public_value(&input.current_state_commitment),
        new_state_commitment: public_value(&input.new_state_commitment),
        deactivate_commitment: public_value(&input.deactivate_commitment),
        expected_poll_id: public_value(&input.expected_poll_id),
    })
}

fn validate_batch_witness_lengths(input: &ProcessMessagesInput) -> ProofResult<()> {
    for (name, actual) in [
        ("currentStateLeaves", input.current_state_leaves.len()),
        (
            "currentStateLeavesPathElements",
            input.current_state_leaves_path_elements.len(),
        ),
        ("activeStateLeaves", input.active_state_leaves.len()),
        (
            "activeStateLeavesPathElements",
            input.active_state_leaves_path_elements.len(),
        ),
        ("currentVoteWeights", input.current_vote_weights.len()),
        (
            "currentVoteWeightsPathElements",
            input.current_vote_weights_path_elements.len(),
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

#[derive(Debug, Clone)]
pub struct Command {
    pub state_index: Field,
    pub vote_option_index: Field,
    pub new_vote_weight: Field,
    pub nonce: Field,
    pub poll_id: Field,
    pub new_pub_key: [Field; 2],
    pub sig_r8: [Field; 2],
    pub sig_s: Field,
    pub packed_command: [Field; 3],
}

pub fn message_to_command(
    message: &Message,
    enc_priv_key: &Field,
    enc_pub_key: &[Field; 2],
) -> ProofResult<Command> {
    let shared_key = ecdh_formatted_priv_key(enc_priv_key, enc_pub_key);
    let decrypted = decrypt_without_check(message, &shared_key, &Field::from(0u32), 7)?;
    let unpacked = unpack_element_high_to_low(&decrypted[0], 7)?;
    let new_vote_weight = decode_vote_weight_96(&unpacked[1], &unpacked[2], &unpacked[3])?;
    Ok(Command {
        poll_id: unpacked[0].clone(),
        nonce: unpacked[6].clone(),
        state_index: unpacked[5].clone(),
        vote_option_index: unpacked[4].clone(),
        new_vote_weight,
        new_pub_key: [decrypted[1].clone(), decrypted[2].clone()],
        sig_r8: [decrypted[4].clone(), decrypted[5].clone()],
        sig_s: decrypted[6].clone(),
        packed_command: [
            decrypted[0].clone(),
            decrypted[1].clone(),
            decrypted[2].clone(),
        ],
    })
}

fn process_batch(
    input: &ProcessMessagesInput,
    packed: &crate::packing::ProcessMessagesPackedVals,
) -> ProofResult<Field> {
    let vo_tree_zero_root = zero_root(input.vote_option_tree_depth)?;
    let mut state_roots = vec![Field::from(0u32); input.batch_size + 1];
    state_roots[input.batch_size] = input.current_state_root.clone();

    for i in (0..input.batch_size).rev() {
        let is_empty = input.enc_pub_keys[i][0].is_zero();
        let command = if is_empty {
            empty_command()
        } else {
            message_to_command(
                &input.msgs[i],
                &input.coord_priv_key,
                &input.enc_pub_keys[i],
            )?
        };
        state_roots[i] = process_one(
            input,
            packed,
            &vo_tree_zero_root,
            i,
            &state_roots[i + 1],
            &command,
        )?;
    }

    Ok(state_roots[0].clone())
}

fn empty_command() -> Command {
    Command {
        state_index: Field::from(0u32),
        vote_option_index: Field::from(0u32),
        new_vote_weight: Field::from(0u32),
        nonce: Field::from(0u32),
        poll_id: Field::from(0u32),
        new_pub_key: [Field::from(0u32), Field::from(0u32)],
        sig_r8: [Field::from(0u32), Field::from(0u32)],
        sig_s: Field::from(0u32),
        packed_command: [Field::from(0u32), Field::from(0u32), Field::from(0u32)],
    }
}

fn process_one(
    input: &ProcessMessagesInput,
    packed: &crate::packing::ProcessMessagesPackedVals,
    vo_tree_zero_root: &Field,
    i: usize,
    current_state_root: &Field,
    command: &Command,
) -> ProofResult<Field> {
    let state_leaf = &input.current_state_leaves[i];
    let transform = state_leaf_transformer(
        input,
        packed,
        state_leaf,
        &input.current_vote_weights[i],
        &input.active_state_leaves[i],
        command,
    )?;

    let max_index = Field::from(pow5(5, input.state_tree_depth));
    let state_index = if transform.is_valid {
        command.state_index.clone()
    } else {
        &max_index - Field::one()
    };
    let current_leaf_hash = state_leaf_hash_digest(state_leaf)?;
    check_inclusion_digest(
        "process state leaf",
        &current_leaf_hash,
        &state_index,
        &input.current_state_leaves_path_elements[i],
        &field_to_digest(current_state_root),
    )?;
    check_inclusion(
        "process active leaf",
        &input.active_state_leaves[i],
        &state_index,
        &input.active_state_leaves_path_elements[i],
        &input.active_state_root,
    )?;

    let vote_index = if transform.is_valid {
        command.vote_option_index.clone()
    } else {
        Field::from(0u32)
    };
    let current_vote_root = root_from_path(
        &input.current_vote_weights[i],
        &vote_index,
        &input.current_vote_weights_path_elements[i],
    )?;
    let expected_vote_root = if state_leaf[3].is_zero() {
        vo_tree_zero_root.clone()
    } else {
        state_leaf[3].clone()
    };
    if current_vote_root != expected_vote_root {
        return Err(ProofError::MerkleRootMismatch {
            name: "current vote weight",
            expected: expected_vote_root,
            actual: current_vote_root,
        });
    }

    let new_vote_weight_leaf = if transform.is_valid {
        command.new_vote_weight.clone()
    } else {
        input.current_vote_weights[i].clone()
    };
    let new_vote_option_root = root_from_path(
        &new_vote_weight_leaf,
        &vote_index,
        &input.current_vote_weights_path_elements[i],
    )?;

    let mut new_state_leaf: [Field; 10] = std::array::from_fn(|_| Field::from(0u32));
    new_state_leaf[0] = transform.new_pub_key[0].clone();
    new_state_leaf[1] = transform.new_pub_key[1].clone();
    new_state_leaf[2] = if transform.is_valid {
        transform.new_balance
    } else {
        state_leaf[2].clone()
    };
    new_state_leaf[3] = if transform.is_valid {
        new_vote_option_root
    } else {
        state_leaf[3].clone()
    };
    new_state_leaf[4] = if transform.is_valid {
        command.nonce.clone()
    } else {
        state_leaf[4].clone()
    };
    new_state_leaf[5] = state_leaf[5].clone();
    new_state_leaf[6] = state_leaf[6].clone();
    new_state_leaf[7] = state_leaf[7].clone();
    new_state_leaf[8] = state_leaf[8].clone();
    new_state_leaf[9] = Field::from(0u32);

    let new_leaf_hash = state_leaf_hash(&new_state_leaf)?;
    root_from_path(
        &new_leaf_hash,
        &state_index,
        &input.current_state_leaves_path_elements[i],
    )
}

struct TransformResult {
    is_valid: bool,
    new_pub_key: [Field; 2],
    new_balance: Field,
}

fn state_leaf_transformer(
    input: &ProcessMessagesInput,
    packed: &crate::packing::ProcessMessagesPackedVals,
    state_leaf: &StateLeaf,
    current_votes_for_option: &Field,
    deactivate: &Field,
    command: &Command,
) -> ProofResult<TransformResult> {
    let msg_valid = message_validator(
        packed,
        state_leaf,
        current_votes_for_option,
        command,
        &input.expected_poll_id,
    )?;
    let active = deactivate.is_zero();
    let is_deactivated_odd = if active && msg_valid.0 {
        decrypt_deactivation_flag(
            &[state_leaf[5].clone(), state_leaf[6].clone()],
            &[state_leaf[7].clone(), state_leaf[8].clone()],
            &input.coord_priv_key,
        )?
        .1
    } else {
        true
    };
    let is_valid = !is_deactivated_odd && active && msg_valid.0;
    Ok(TransformResult {
        is_valid,
        new_pub_key: if is_valid {
            command.new_pub_key.clone()
        } else {
            [state_leaf[0].clone(), state_leaf[1].clone()]
        },
        new_balance: msg_valid.1,
    })
}

fn message_validator(
    packed: &crate::packing::ProcessMessagesPackedVals,
    state_leaf: &StateLeaf,
    current_votes_for_option: &Field,
    command: &Command,
    expected_poll_id: &Field,
) -> ProofResult<(bool, Field)> {
    let state_index_ok = command.state_index <= packed.num_sign_ups;
    let vote_option_ok = command.vote_option_index < packed.max_vote_options;
    let nonce_ok = state_leaf[4].clone() + Field::one() == command.nonce;
    let poll_ok = command.poll_id == *expected_poll_id;
    let sig_ok = if state_index_ok && vote_option_ok && nonce_ok && poll_ok {
        verify_command_signature(
            &[state_leaf[0].clone(), state_leaf[1].clone()],
            &command.sig_r8,
            &command.sig_s,
            &command.packed_command,
        )?
    } else {
        false
    };
    let vote_weight_ok = &command.new_vote_weight <= max_vote_weight();

    let is_quad = packed.is_quadratic_cost == Field::one();
    let current_cost = if is_quad {
        current_votes_for_option * current_votes_for_option
    } else {
        current_votes_for_option.clone()
    };
    let cost = if is_quad {
        &command.new_vote_weight * &command.new_vote_weight
    } else {
        command.new_vote_weight.clone()
    };
    let available = &state_leaf[2] + &current_cost;
    let sufficient = available >= cost;
    let new_balance = if sufficient {
        available - cost
    } else {
        Field::from(0u32)
    };

    Ok((
        sig_ok
            && sufficient
            && vote_weight_ok
            && nonce_ok
            && state_index_ok
            && vote_option_ok
            && poll_ok,
        new_balance,
    ))
}

pub enum EmptyRule {
    EncPubKeyX,
    Message0,
}

/// Mirrors the `MessageHasher` loop in `ProcessMessages` and `ProcessDeactivateMessages`.
pub fn message_chain(
    start: &Field,
    msgs: &[Message],
    enc_pub_keys: &[[Field; 2]],
    empty_rule: EmptyRule,
) -> ProofResult<Field> {
    let mut current = start.clone();
    for (msg, enc_pub_key) in msgs.iter().zip(enc_pub_keys.iter()) {
        let is_empty = match empty_rule {
            EmptyRule::EncPubKeyX => enc_pub_key[0].is_zero(),
            EmptyRule::Message0 => msg[0].is_zero(),
        };
        if !is_empty {
            let previous = current;
            let hash_input: [Field; 13] = std::array::from_fn(|idx| match idx {
                0..=9 => msg[idx].clone(),
                10 => enc_pub_key[0].clone(),
                11 => enc_pub_key[1].clone(),
                12 => previous.clone(),
                _ => unreachable!("Hasher13 has exactly 13 inputs"),
            });
            current = hash13(&hash_input)?;
        }
    }
    Ok(current)
}
