use crate::circuits::process_messages::{message_chain, EmptyRule};
use crate::crypto::{
    ecdh_formatted_priv_key, native_encrypt_for_testing, native_rerandomize_ciphertext,
    native_sign_command_for_testing, private_to_pub_key,
};
use crate::error::ProofResult;
use crate::field::Field;
use crate::hash_backend::{hash_fields, hash_pair, hash_public_inputs, hash_state_leaf};
use crate::merkle::{hash5_exact, root_from_path, state_leaf_hash, zero_root};
use crate::{
    AddNewKeyInput, Message, PathElement, ProcessDeactivateInput, ProcessMessagesInput,
    ProverInput, TallyVotesInput, VOTE_ROW_WORDS,
};
use num_traits::ToPrimitive;

pub fn built_in_input(name: &str) -> ProofResult<Option<ProverInput>> {
    let input = match name {
        "process-messages-native-2-1-5-full" => {
            ProverInput::ProcessMessages(process_messages_native_2_1_5_full()?)
        }
        "process-messages-native-1-1" => {
            ProverInput::ProcessMessages(process_messages_native_1_1()?)
        }
        "process-messages-native-2-1-5" => {
            ProverInput::ProcessMessages(process_messages_native_2_1_5()?)
        }
        "tally-votes-native-2-1-1" => ProverInput::TallyVotes(tally_votes_native_2_1_1()?),
        "process-deactivate-native-2-5" => {
            ProverInput::ProcessDeactivate(process_deactivate_native_2_5()?)
        }
        "add-new-key-native-2" => ProverInput::AddNewKey(add_new_key_native_2()?),
        _ => return Ok(None),
    };
    Ok(Some(input))
}

pub fn supported_inputs() -> &'static str {
    "process-messages-native-1-1, process-messages-native-2-1-5, process-messages-native-2-1-5-full, tally-votes-native-2-1-1, process-deactivate-native-2-5, add-new-key-native-2"
}

pub fn process_messages_native_1_1() -> ProofResult<ProcessMessagesInput> {
    build_process_messages_input(1, 1, 1, 1)
}

pub fn process_messages_native_2_1_5() -> ProofResult<ProcessMessagesInput> {
    build_process_messages_input(2, 1, 5, 1)
}

pub fn process_messages_native_2_1_5_full() -> ProofResult<ProcessMessagesInput> {
    build_process_messages_input(2, 1, 5, 5)
}

fn build_process_messages_input(
    state_tree_depth: usize,
    vote_option_tree_depth: usize,
    batch_size: usize,
    valid_messages: usize,
) -> ProofResult<ProcessMessagesInput> {
    let zero = Field::from(0u32);
    let poll_id = Field::from(1u32);
    let coord_priv_key = Field::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let c1 = [zero.clone(), zero.clone()];
    let c2 = [zero.clone(), zero.clone()];
    let vote_path = vec![[zero; 4]; vote_option_tree_depth];
    let tree_size = 5usize.pow(state_tree_depth as u32);

    let mut msgs = vec![[zero; 10]; batch_size];
    let mut enc_pub_keys = vec![[zero.clone(), zero.clone()]; batch_size];
    let zero_state_leaf = [zero; 10];
    let zero_state_leaf_hash = hash_state_leaf(&zero_state_leaf)?;
    let mut current_state_leaves = vec![zero_state_leaf.clone(); batch_size];
    let mut current_vote_weights = vec![zero.clone(); batch_size];
    let mut current_vote_weights_paths = vec![vote_path.clone(); batch_size];
    let mut state_hashes = vec![zero_state_leaf_hash; tree_size];
    let mut new_state_leaves = vec![zero_state_leaf.clone(); batch_size];
    let mut state_indices = vec![Field::from(tree_size - 1); batch_size];

    for i in 0..valid_messages {
        let state_index = Field::from((i + 1) as u32);
        let vote_option_index = Field::from((i % 5) as u32);
        let nonce = Field::from(1u32);
        let new_vote_weight = Field::from((i + 2) as u32);
        let initial_balance = Field::from(20u32);
        let user_priv_key = Field::from(2002u32 + i as u32);
        let user_pub_key = private_to_pub_key(&user_priv_key);
        let new_priv_key = Field::from(3003u32 + i as u32);
        let new_pub_key = private_to_pub_key(&new_priv_key);
        let enc_priv_key = Field::from(4004u32 + i as u32);
        let enc_pub_key = private_to_pub_key(&enc_priv_key);

        let packed_command = pack_command_data(
            &poll_id,
            &zero,
            &zero,
            &new_vote_weight,
            &vote_option_index,
            &state_index,
            &nonce,
        );
        let command = [
            packed_command,
            new_pub_key[0].clone(),
            new_pub_key[1].clone(),
        ];
        let message =
            encrypt_signed_command(&coord_priv_key, &enc_pub_key, &user_priv_key, command)?;

        let state_leaf = [
            user_pub_key[0].clone(),
            user_pub_key[1].clone(),
            initial_balance.clone(),
            zero.clone(),
            zero.clone(),
            c1[0].clone(),
            c1[1].clone(),
            c2[0].clone(),
            c2[1].clone(),
            zero.clone(),
        ];
        let new_vote_root = root_from_path(&new_vote_weight, &vote_option_index, &vote_path)?;
        let new_state_leaf = [
            new_pub_key[0].clone(),
            new_pub_key[1].clone(),
            &initial_balance - &new_vote_weight,
            new_vote_root,
            nonce,
            c1[0].clone(),
            c1[1].clone(),
            c2[0].clone(),
            c2[1].clone(),
            zero.clone(),
        ];

        msgs[i] = message;
        enc_pub_keys[i] = enc_pub_key;
        current_state_leaves[i] = state_leaf.clone();
        current_vote_weights[i] = zero.clone();
        current_vote_weights_paths[i] = vote_path.clone();
        state_indices[i] = state_index.clone();
        state_hashes[state_index_as_usize(&state_index)?] = hash_state_leaf(&state_leaf)?;
        new_state_leaves[i] = new_state_leaf;
    }

    let (current_state_root, _) = quin_root_and_path(&state_hashes, state_tree_depth, 0)?;
    let mut current_state_paths = vec![Vec::new(); batch_size];
    for i in (0..batch_size).rev() {
        let state_index = state_index_as_usize(&state_indices[i])?;
        let (_, path) = quin_root_and_path(&state_hashes, state_tree_depth, state_index)?;
        current_state_paths[i] = path;
        if i < valid_messages {
            state_hashes[state_index] = hash_state_leaf(&new_state_leaves[i])?;
        }
    }
    let (new_state_root, _) = quin_root_and_path(&state_hashes, state_tree_depth, 0)?;

    let active_state_root = zero_root(state_tree_depth)?;
    let deactivate_root = zero_root(state_tree_depth + 2)?;
    let current_state_salt = Field::from(11u32);
    let new_state_salt = Field::from(12u32);
    let current_state_commitment = hash_pair(&current_state_root, &current_state_salt);
    let new_state_commitment = hash_pair(&new_state_root, &new_state_salt);
    let deactivate_commitment = hash_pair(&active_state_root, &deactivate_root);
    let packed_vals = Field::from(5u32) + (Field::from(valid_messages as u32) << 32usize);
    let batch_start_hash = zero.clone();
    let batch_end_hash = message_chain(
        &batch_start_hash,
        &msgs,
        &enc_pub_keys,
        EmptyRule::EncPubKeyX,
    )?;
    let coord_pub_key_hash = hash_fields(&coord_pub_key);
    let input_hash = hash_public_inputs(&[
        packed_vals.clone(),
        coord_pub_key_hash,
        batch_start_hash.clone(),
        batch_end_hash.clone(),
        current_state_commitment.clone(),
        new_state_commitment.clone(),
        deactivate_commitment.clone(),
        poll_id.clone(),
    ]);

    Ok(ProcessMessagesInput {
        state_tree_depth,
        vote_option_tree_depth,
        batch_size,
        input_hash,
        packed_vals,
        expected_poll_id: poll_id,
        batch_start_hash,
        batch_end_hash,
        coord_priv_key,
        coord_pub_key,
        msgs,
        enc_pub_keys,
        current_state_root,
        current_state_leaves,
        current_state_leaves_path_elements: current_state_paths,
        current_state_commitment,
        current_state_salt,
        new_state_commitment,
        new_state_salt,
        active_state_root,
        deactivate_root,
        deactivate_commitment,
        active_state_leaves: vec![zero.clone(); batch_size],
        active_state_leaves_path_elements: vec![zero_sibling_path(state_tree_depth)?; batch_size],
        current_vote_weights,
        current_vote_weights_path_elements: current_vote_weights_paths,
    })
}

pub fn tally_votes_native_2_1_1() -> ProofResult<TallyVotesInput> {
    let state_tree_depth = 2;
    let int_state_tree_depth = 1;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let num_vote_options = 5;
    let zero = Field::from(0u32);

    let zero_state_leaf = [zero; 10];
    let state_leaf_hash = state_leaf_hash(&zero_state_leaf)?;
    let state_subroot = hash_fields(&vec![state_leaf_hash; batch_size]);
    let state_path_elements = vec![[zero; 4]];
    let state_root = root_from_path(&state_subroot, &zero, &state_path_elements)?;
    let state_salt = Field::from(21u32);
    let state_commitment = hash_pair(&state_root, &state_salt);

    let current_tally_commitment = zero.clone();
    let current_results = vec![zero.clone(); num_vote_options];
    let votes = vec![[zero; VOTE_ROW_WORDS]; batch_size];
    let new_results_root_salt = Field::from(22u32);
    let new_results_root = hash_fields(&current_results);
    let new_tally_commitment = hash_pair(&new_results_root, &new_results_root_salt);
    let packed_vals = Field::from(5u32) << 32usize;
    let input_hash = hash_public_inputs(&[
        packed_vals.clone(),
        state_commitment.clone(),
        current_tally_commitment.clone(),
        new_tally_commitment.clone(),
    ]);

    Ok(TallyVotesInput {
        state_tree_depth,
        int_state_tree_depth,
        vote_option_tree_depth,
        input_hash,
        packed_vals,
        state_root,
        state_salt,
        state_commitment,
        current_tally_commitment,
        new_tally_commitment,
        state_leaf: vec![zero_state_leaf; batch_size],
        state_path_elements,
        votes,
        current_results,
        current_results_root_salt: zero,
        new_results_root_salt,
    })
}

pub fn process_deactivate_native_2_5() -> ProofResult<ProcessDeactivateInput> {
    let state_tree_depth = 2;
    let batch_size = 5;
    let zero = Field::from(0u32);
    let poll_id = Field::from(1u32);
    let coord_priv_key = Field::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let state_tree_size = 5usize.pow(state_tree_depth as u32);
    let deactivate_tree_depth = state_tree_depth + 2;
    let deactivate_tree_size = 5usize.pow(deactivate_tree_depth as u32);
    let deactivate_index0 = Field::from(17u32);

    let zero_state_leaf = [zero; 10];
    let zero_state_leaf_hash = hash_state_leaf(&zero_state_leaf)?;
    let mut state_hashes = vec![zero_state_leaf_hash; state_tree_size];
    let mut current_state_leaves = Vec::with_capacity(batch_size);
    let mut state_indices = Vec::with_capacity(batch_size);
    let mut msgs = Vec::with_capacity(batch_size);
    let mut enc_pub_keys = Vec::with_capacity(batch_size);
    let mut c1 = Vec::with_capacity(batch_size);
    let mut c2 = Vec::with_capacity(batch_size);

    for i in 0..batch_size {
        let state_index = Field::from((i + 1) as u32);
        let user_priv_key = Field::from(6001u32 + i as u32);
        let user_pub_key = private_to_pub_key(&user_priv_key);
        let new_priv_key = Field::from(7001u32 + i as u32);
        let new_pub_key = private_to_pub_key(&new_priv_key);
        let enc_priv_key = Field::from(8001u32 + i as u32);
        let enc_pub_key = private_to_pub_key(&enc_priv_key);
        let packed_command = pack_command_data(
            &poll_id,
            &zero,
            &zero,
            &zero,
            &zero,
            &state_index,
            &Field::from(1u32),
        );
        let command = [
            packed_command,
            new_pub_key[0].clone(),
            new_pub_key[1].clone(),
        ];
        let message =
            encrypt_signed_command(&coord_priv_key, &enc_pub_key, &user_priv_key, command)?;
        let state_leaf = [
            user_pub_key[0].clone(),
            user_pub_key[1].clone(),
            Field::from(10u32),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
        ];
        state_hashes[state_index_as_usize(&state_index)?] = hash_state_leaf(&state_leaf)?;
        current_state_leaves.push(state_leaf);
        state_indices.push(state_index);
        msgs.push(message);
        enc_pub_keys.push(enc_pub_key);
        c1.push([zero.clone(), zero.clone()]);
        c2.push([zero.clone(), zero.clone()]);
    }

    let (current_state_root, _) = quin_root_and_path(&state_hashes, state_tree_depth, 0)?;
    let current_active_state_root = zero_root(state_tree_depth)?;
    let current_deactivate_root = zero_root(deactivate_tree_depth)?;
    let current_deactivate_commitment =
        hash_pair(&current_active_state_root, &current_deactivate_root);

    let mut active_hashes = vec![zero.clone(); state_tree_size];
    let mut deactivate_hashes = vec![zero.clone(); deactivate_tree_size];
    let mut current_state_paths = Vec::with_capacity(batch_size);
    let mut active_paths = Vec::with_capacity(batch_size);
    let mut deactivate_paths = Vec::with_capacity(batch_size);
    let mut current_active_state = Vec::with_capacity(batch_size);
    let mut new_active_state = Vec::with_capacity(batch_size);

    for i in 0..batch_size {
        let state_index = state_index_as_usize(&state_indices[i])?;
        let (_, state_path) = quin_root_and_path(&state_hashes, state_tree_depth, state_index)?;
        let (_, active_path) = quin_root_and_path(&active_hashes, state_tree_depth, state_index)?;
        let deactivate_index = state_index_as_usize(&(deactivate_index0.clone() + Field::from(i)))?;
        let (_, deactivate_path) =
            quin_root_and_path(&deactivate_hashes, deactivate_tree_depth, deactivate_index)?;

        let shared_key = ecdh_formatted_priv_key(
            &coord_priv_key,
            &[
                current_state_leaves[i][0].clone(),
                current_state_leaves[i][1].clone(),
            ],
        );
        let shared_key_hash = hash_fields(&shared_key);
        let deactivate_leaf = hash_fields(&[
            c1[i][0].clone(),
            c1[i][1].clone(),
            c2[i][0].clone(),
            c2[i][1].clone(),
            shared_key_hash,
        ]);
        let active_leaf = hash_fields(&[state_indices[i].clone(), poll_id.clone()]);

        current_state_paths.push(state_path);
        active_paths.push(active_path);
        deactivate_paths.push(deactivate_path);
        current_active_state.push(zero.clone());
        new_active_state.push(active_leaf.clone());
        active_hashes[state_index] = active_leaf;
        deactivate_hashes[deactivate_index] = deactivate_leaf;
    }

    let (new_active_root, _) = quin_root_and_path(&active_hashes, state_tree_depth, 0)?;
    let (new_deactivate_root, _) =
        quin_root_and_path(&deactivate_hashes, deactivate_tree_depth, 0)?;
    let new_deactivate_commitment = hash_pair(&new_active_root, &new_deactivate_root);
    let batch_start_hash = zero.clone();
    let batch_end_hash =
        message_chain(&batch_start_hash, &msgs, &enc_pub_keys, EmptyRule::Message0)?;
    let coord_pub_key_hash = hash_fields(&coord_pub_key);
    let input_hash = hash_public_inputs(&[
        new_deactivate_root.clone(),
        coord_pub_key_hash,
        batch_start_hash.clone(),
        batch_end_hash.clone(),
        current_deactivate_commitment.clone(),
        new_deactivate_commitment.clone(),
        current_state_root.clone(),
        poll_id.clone(),
    ]);

    Ok(ProcessDeactivateInput {
        state_tree_depth,
        batch_size,
        input_hash,
        expected_poll_id: poll_id,
        current_active_state_root,
        current_deactivate_root,
        batch_start_hash,
        batch_end_hash,
        coord_priv_key,
        coord_pub_key,
        msgs,
        enc_pub_keys,
        c1,
        c2,
        current_active_state,
        new_active_state,
        deactivate_index0,
        current_state_root,
        current_state_leaves,
        current_state_leaves_path_elements: current_state_paths,
        active_state_leaves_path_elements: active_paths,
        deactivate_leaves_path_elements: deactivate_paths,
        current_deactivate_commitment,
        new_deactivate_root,
        new_deactivate_commitment,
    })
}

pub fn add_new_key_native_2() -> ProofResult<AddNewKeyInput> {
    let state_tree_depth = 2;
    let deactivate_tree_depth = state_tree_depth + 2;
    let zero = Field::from(0u32);
    let poll_id = Field::from(1u32);
    let coord_priv_key = Field::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let old_private_key = Field::from(6001u32);
    let new_pub_key = private_to_pub_key(&Field::from(9001u32));
    let c1 = [zero.clone(), zero.clone()];
    let c2 = [zero.clone(), zero.clone()];
    let shared_key = ecdh_formatted_priv_key(&old_private_key, &coord_pub_key);
    let shared_key_hash = hash_fields(&shared_key);
    let deactivate_leaf = hash_fields(&[
        c1[0].clone(),
        c1[1].clone(),
        c2[0].clone(),
        c2[1].clone(),
        shared_key_hash,
    ]);
    let deactivate_index = Field::from(17u32);
    let mut leaves = vec![zero.clone(); 5usize.pow(deactivate_tree_depth as u32)];
    leaves[state_index_as_usize(&deactivate_index)?] = deactivate_leaf.clone();
    let (deactivate_root, deactivate_leaf_path_elements) = quin_root_and_path(
        &leaves,
        deactivate_tree_depth,
        state_index_as_usize(&deactivate_index)?,
    )?;
    let nullifier = hash_pair(&old_private_key, &poll_id);
    let random_val = Field::from(42u32);
    let (d1, d2) = native_rerandomize_ciphertext(&coord_pub_key, &c1, &c2, &random_val);
    let coord_pub_key_hash = hash_fields(&coord_pub_key);
    let new_pub_key_hash = hash_fields(&new_pub_key);
    let input_hash = hash_public_inputs(&[
        deactivate_root.clone(),
        coord_pub_key_hash,
        nullifier.clone(),
        d1[0].clone(),
        d1[1].clone(),
        d2[0].clone(),
        d2[1].clone(),
        new_pub_key_hash,
        poll_id.clone(),
    ]);

    Ok(AddNewKeyInput {
        state_tree_depth,
        input_hash,
        coord_pub_key,
        deactivate_root,
        deactivate_index,
        deactivate_leaf,
        c1,
        c2,
        random_val,
        d1,
        d2,
        deactivate_leaf_path_elements,
        nullifier,
        old_private_key,
        new_pub_key,
        poll_id,
    })
}

fn encrypt_signed_command(
    coord_priv_key: &Field,
    enc_pub_key: &[Field; 2],
    user_priv_key: &Field,
    command: [Field; 3],
) -> ProofResult<Message> {
    let zero = Field::from(0u32);
    let (sig_r8, sig_s) = native_sign_command_for_testing(user_priv_key, &command);
    let shared_key = ecdh_formatted_priv_key(coord_priv_key, enc_pub_key);
    let mut plaintext = vec![
        command[0].clone(),
        command[1].clone(),
        command[2].clone(),
        zero.clone(),
        sig_r8[0].clone(),
        sig_r8[1].clone(),
        sig_s,
    ];
    plaintext.resize(9, zero.clone());
    message_from_ciphertext(native_encrypt_for_testing(
        &plaintext,
        &shared_key,
        &zero,
        7,
    )?)
}

fn message_from_ciphertext(ciphertext: Vec<Field>) -> ProofResult<Message> {
    ciphertext
        .try_into()
        .map_err(|ciphertext: Vec<Field>| crate::ProofError::InvalidLength {
            name: "native message ciphertext",
            expected: 10,
            actual: ciphertext.len(),
        })
}

fn quin_root_and_path(
    leaves: &[Field],
    depth: usize,
    index: usize,
) -> ProofResult<(Field, Vec<PathElement>)> {
    let expected = 5usize.pow(depth as u32);
    if leaves.len() != expected {
        return Err(crate::ProofError::InvalidLength {
            name: "sample quin leaves",
            expected,
            actual: leaves.len(),
        });
    }
    let mut level = leaves.to_vec();
    let mut idx = index;
    let mut path = Vec::with_capacity(depth);
    for _ in 0..depth {
        let group_start = (idx / 5) * 5;
        let child_index = idx % 5;
        let mut siblings = [Field::from(0u32); 4];
        let mut sibling_idx = 0;
        for child in 0..5 {
            if child != child_index {
                siblings[sibling_idx] = level[group_start + child].clone();
                sibling_idx += 1;
            }
        }
        path.push(siblings);

        let mut next = Vec::with_capacity(level.len() / 5);
        for chunk in level.chunks(5) {
            next.push(hash5_exact(chunk)?);
        }
        level = next;
        idx /= 5;
    }
    Ok((level[0].clone(), path))
}

fn state_index_as_usize(value: &Field) -> ProofResult<usize> {
    value
        .to_usize()
        .ok_or_else(|| crate::ProofError::Crypto("state index does not fit usize".to_string()))
}

fn zero_sibling_path(depth: usize) -> ProofResult<Vec<PathElement>> {
    let mut path = Vec::with_capacity(depth);
    for level in 0..depth {
        path.push([zero_root(level)?; 4]);
    }
    Ok(path)
}

fn pack_command_data(
    poll_id: &Field,
    vote_weight_high: &Field,
    vote_weight_mid: &Field,
    vote_weight_low: &Field,
    vote_option_index: &Field,
    state_index: &Field,
    nonce: &Field,
) -> Field {
    (*poll_id << 192usize)
        + (*vote_weight_high << 160usize)
        + (*vote_weight_mid << 128usize)
        + (*vote_weight_low << 96usize)
        + (*vote_option_index << 64usize)
        + (*state_index << 32usize)
        + *nonce
}
