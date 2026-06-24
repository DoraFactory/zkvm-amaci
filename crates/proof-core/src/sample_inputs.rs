#[cfg(feature = "zkvm-native-crypto")]
use crate::circuits::process_messages::{message_chain, EmptyRule};
use crate::crypto::private_to_pub_key;
#[cfg(feature = "zkvm-native-crypto")]
use crate::crypto::{
    ecdh_formatted_priv_key, native_encrypt_for_testing, native_sign_command_for_testing,
};
use crate::error::ProofResult;
use crate::field::Field;
#[cfg(feature = "zkvm-native-crypto")]
use crate::hash_backend::hash_state_leaf;
use crate::hash_backend::{hash_fields, hash_pair, hash_public_inputs};
#[cfg(feature = "zkvm-native-crypto")]
use crate::merkle::hash5_exact;
use crate::merkle::{root_from_path, state_leaf_hash, zero_root};
use crate::{ProcessMessagesInput, ProverInput, TallyVotesInput};
use num_bigint::BigUint;

pub fn built_in_input(name: &str) -> ProofResult<Option<ProverInput>> {
    let input = match name {
        "process-messages-2-1-5" | "process-messages" => {
            ProverInput::ProcessMessages(process_messages_2_1_5()?)
        }
        "tally-votes-2-1-1" | "tally-votes" => ProverInput::TallyVotes(tally_votes_2_1_1()?),
        #[cfg(feature = "zkvm-native-crypto")]
        "process-messages-native-1-1" | "native-process-messages" => {
            ProverInput::ProcessMessages(process_messages_native_1_1()?)
        }
        #[cfg(feature = "zkvm-native-crypto")]
        "process-messages-native-2-1-5" => {
            ProverInput::ProcessMessages(process_messages_native_2_1_5()?)
        }
        _ => return Ok(None),
    };
    Ok(Some(input))
}

pub fn supported_inputs() -> &'static str {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        "process-messages-2-1-5, tally-votes-2-1-1, process-messages-native-1-1, process-messages-native-2-1-5"
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        "process-messages-2-1-5, tally-votes-2-1-1"
    }
}

pub fn process_messages_2_1_5() -> ProofResult<ProcessMessagesInput> {
    let state_tree_depth = 2;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let coord_priv_key = one.clone();
    let coord_pub_key = private_to_pub_key(&coord_priv_key);

    let state_leaf = vec![zero.clone(); 10];
    let state_leaf_hash = state_leaf_hash(&state_leaf)?;
    let state_index = BigUint::from(24u32);
    let state_path = zero_sibling_path(state_tree_depth)?;
    let current_state_root = root_from_path(&state_leaf_hash, &state_index, &state_path)?;
    let current_state_salt = BigUint::from(11u32);
    let new_state_salt = BigUint::from(12u32);
    let current_state_commitment = hash_pair(&current_state_root, &current_state_salt);
    let new_state_commitment = hash_pair(&current_state_root, &new_state_salt);

    let active_state_root = zero_root(state_tree_depth)?;
    let deactivate_root = zero_root(state_tree_depth + 2)?;
    let deactivate_commitment = hash_pair(&active_state_root, &deactivate_root);

    let packed_vals = BigUint::from(5u32) + (BigUint::from(1u32) << 32usize);
    let expected_poll_id = one;
    let batch_start_hash = zero.clone();
    let batch_end_hash = zero.clone();
    let coord_pub_key_hash = hash_fields(&coord_pub_key);
    let input_hash = hash_public_inputs(&[
        packed_vals.clone(),
        coord_pub_key_hash,
        batch_start_hash.clone(),
        batch_end_hash.clone(),
        current_state_commitment.clone(),
        new_state_commitment.clone(),
        deactivate_commitment.clone(),
        expected_poll_id.clone(),
    ]);

    Ok(ProcessMessagesInput {
        state_tree_depth,
        vote_option_tree_depth,
        batch_size,
        input_hash,
        packed_vals,
        expected_poll_id,
        batch_start_hash,
        batch_end_hash,
        coord_priv_key,
        coord_pub_key,
        msgs: vec![vec![zero.clone(); 10]; batch_size],
        enc_pub_keys: vec![[zero.clone(), zero.clone()]; batch_size],
        current_state_root,
        current_state_leaves: vec![state_leaf; batch_size],
        current_state_leaves_path_elements: vec![state_path; batch_size],
        current_state_commitment,
        current_state_salt,
        new_state_commitment,
        new_state_salt,
        active_state_root,
        deactivate_root,
        deactivate_commitment,
        active_state_leaves: vec![zero.clone(); batch_size],
        active_state_leaves_path_elements: vec![zero_sibling_path(state_tree_depth)?; batch_size],
        current_vote_weights: vec![zero.clone(); batch_size],
        current_vote_weights_path_elements: vec![
            vec![vec![zero.clone(); 4]; vote_option_tree_depth];
            batch_size
        ],
    })
}

pub fn tally_votes_2_1_1() -> ProofResult<TallyVotesInput> {
    let state_tree_depth = 2;
    let int_state_tree_depth = 1;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let num_vote_options = 5;
    let zero = BigUint::from(0u32);

    let zero_state_leaf = vec![zero.clone(); 10];
    let state_leaf_hash = state_leaf_hash(&zero_state_leaf)?;
    let state_subroot = hash_fields(&vec![state_leaf_hash; batch_size]);
    let state_path_elements = vec![vec![zero.clone(); 4]];
    let state_root = root_from_path(&state_subroot, &zero, &state_path_elements)?;
    let state_salt = BigUint::from(21u32);
    let state_commitment = hash_pair(&state_root, &state_salt);

    let current_tally_commitment = zero.clone();
    let current_results = vec![zero.clone(); num_vote_options];
    let votes = vec![vec![zero.clone(); num_vote_options]; batch_size];
    let new_results_root_salt = BigUint::from(22u32);
    let new_results_root = hash_fields(&current_results);
    let new_tally_commitment = hash_pair(&new_results_root, &new_results_root_salt);
    let packed_vals = BigUint::from(5u32) << 32usize;
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

#[cfg(feature = "zkvm-native-crypto")]
pub fn process_messages_native_1_1() -> ProofResult<ProcessMessagesInput> {
    let state_tree_depth = 1;
    let vote_option_tree_depth = 1;
    let batch_size = 1;
    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let coord_priv_key = BigUint::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let user_priv_key = BigUint::from(2002u32);
    let user_pub_key = private_to_pub_key(&user_priv_key);
    let new_priv_key = BigUint::from(3003u32);
    let new_pub_key = private_to_pub_key(&new_priv_key);
    let enc_priv_key = BigUint::from(4004u32);
    let enc_pub_key = private_to_pub_key(&enc_priv_key);

    let state_index = one.clone();
    let vote_option_index = zero.clone();
    let nonce = one.clone();
    let poll_id = one.clone();
    let new_vote_weight = BigUint::from(3u32);
    let initial_balance = BigUint::from(10u32);
    let c1 = [zero.clone(), zero.clone()];
    let c2 = [zero.clone(), zero.clone()];

    let packed_command = [
        pack_command_data(
            &poll_id,
            &zero,
            &zero,
            &new_vote_weight,
            &vote_option_index,
            &state_index,
            &nonce,
        ),
        new_pub_key[0].clone(),
        new_pub_key[1].clone(),
    ];
    let (sig_r8, sig_s) = native_sign_command_for_testing(&user_priv_key, &packed_command);

    let shared_key = ecdh_formatted_priv_key(&coord_priv_key, &enc_pub_key);
    let mut plaintext = vec![
        packed_command[0].clone(),
        packed_command[1].clone(),
        packed_command[2].clone(),
        zero.clone(),
        sig_r8[0].clone(),
        sig_r8[1].clone(),
        sig_s,
    ];
    plaintext.resize(9, zero.clone());
    let message = native_encrypt_for_testing(&plaintext, &shared_key, &zero, 7)?;

    let state_path = vec![vec![zero.clone(); 4]; state_tree_depth];
    let vote_path = vec![vec![zero.clone(); 4]; vote_option_tree_depth];
    let state_leaf = vec![
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
    let state_leaf_hash = hash_state_leaf(&state_leaf)?;
    let current_state_root = root_from_path(&state_leaf_hash, &state_index, &state_path)?;
    let active_state_root = root_from_path(&zero, &state_index, &state_path)?;
    let current_state_salt = BigUint::from(11u32);
    let new_state_salt = BigUint::from(12u32);
    let current_state_commitment = hash_pair(&current_state_root, &current_state_salt);

    let new_vote_root = root_from_path(&new_vote_weight, &vote_option_index, &vote_path)?;
    let new_state_leaf = vec![
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
    let new_state_root = root_from_path(
        &hash_state_leaf(&new_state_leaf)?,
        &state_index,
        &state_path,
    )?;
    let new_state_commitment = hash_pair(&new_state_root, &new_state_salt);

    let deactivate_root = zero_root(state_tree_depth + 2)?;
    let deactivate_commitment = hash_pair(&active_state_root, &deactivate_root);
    let packed_vals = BigUint::from(5u32) + (BigUint::from(1u32) << 32usize);
    let batch_start_hash = zero.clone();
    let batch_end_hash = message_chain(
        &batch_start_hash,
        std::slice::from_ref(&message),
        &[enc_pub_key.clone()],
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
        msgs: vec![message],
        enc_pub_keys: vec![enc_pub_key],
        current_state_root,
        current_state_leaves: vec![state_leaf],
        current_state_leaves_path_elements: vec![state_path.clone()],
        current_state_commitment,
        current_state_salt,
        new_state_commitment,
        new_state_salt,
        active_state_root,
        deactivate_root,
        deactivate_commitment,
        active_state_leaves: vec![zero.clone()],
        active_state_leaves_path_elements: vec![state_path],
        current_vote_weights: vec![zero.clone()],
        current_vote_weights_path_elements: vec![vote_path],
    })
}

#[cfg(feature = "zkvm-native-crypto")]
pub fn process_messages_native_2_1_5() -> ProofResult<ProcessMessagesInput> {
    let state_tree_depth = 2;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let coord_priv_key = BigUint::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let user_priv_key = BigUint::from(2002u32);
    let user_pub_key = private_to_pub_key(&user_priv_key);
    let new_priv_key = BigUint::from(3003u32);
    let new_pub_key = private_to_pub_key(&new_priv_key);
    let enc_priv_key = BigUint::from(4004u32);
    let enc_pub_key = private_to_pub_key(&enc_priv_key);

    let state_index = one.clone();
    let vote_option_index = zero.clone();
    let nonce = one.clone();
    let poll_id = one.clone();
    let new_vote_weight = BigUint::from(3u32);
    let initial_balance = BigUint::from(10u32);
    let c1 = [zero.clone(), zero.clone()];
    let c2 = [zero.clone(), zero.clone()];

    let packed_command = [
        pack_command_data(
            &poll_id,
            &zero,
            &zero,
            &new_vote_weight,
            &vote_option_index,
            &state_index,
            &nonce,
        ),
        new_pub_key[0].clone(),
        new_pub_key[1].clone(),
    ];
    let (sig_r8, sig_s) = native_sign_command_for_testing(&user_priv_key, &packed_command);
    let shared_key = ecdh_formatted_priv_key(&coord_priv_key, &enc_pub_key);
    let mut plaintext = vec![
        packed_command[0].clone(),
        packed_command[1].clone(),
        packed_command[2].clone(),
        zero.clone(),
        sig_r8[0].clone(),
        sig_r8[1].clone(),
        sig_s,
    ];
    plaintext.resize(9, zero.clone());
    let message = native_encrypt_for_testing(&plaintext, &shared_key, &zero, 7)?;

    let zero_state_leaf = vec![zero.clone(); 10];
    let state_leaf = vec![
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
    let zero_state_leaf_hash = hash_state_leaf(&zero_state_leaf)?;
    let state_leaf_hash = hash_state_leaf(&state_leaf)?;

    let mut initial_state_hashes = vec![zero.clone(); 25];
    initial_state_hashes[1] = state_leaf_hash;
    initial_state_hashes[24] = zero_state_leaf_hash.clone();
    let (current_state_root, valid_state_path) =
        quin_root_and_path(&initial_state_hashes, state_tree_depth, 1)?;
    let (_, empty_state_path) = quin_root_and_path(&initial_state_hashes, state_tree_depth, 24)?;

    let vote_path = vec![vec![zero.clone(); 4]; vote_option_tree_depth];
    let active_state_root = zero_root(state_tree_depth)?;
    let current_state_salt = BigUint::from(11u32);
    let new_state_salt = BigUint::from(12u32);
    let current_state_commitment = hash_pair(&current_state_root, &current_state_salt);

    let new_vote_root = root_from_path(&new_vote_weight, &vote_option_index, &vote_path)?;
    let new_state_leaf = vec![
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
    let mut new_state_hashes = initial_state_hashes;
    new_state_hashes[1] = hash_state_leaf(&new_state_leaf)?;
    let (new_state_root, _) = quin_root_and_path(&new_state_hashes, state_tree_depth, 1)?;
    let new_state_commitment = hash_pair(&new_state_root, &new_state_salt);

    let deactivate_root = zero_root(state_tree_depth + 2)?;
    let deactivate_commitment = hash_pair(&active_state_root, &deactivate_root);
    let packed_vals = BigUint::from(5u32) + (BigUint::from(1u32) << 32usize);
    let batch_start_hash = zero.clone();

    let mut msgs = vec![vec![zero.clone(); 10]; batch_size];
    msgs[0] = message;
    let mut enc_pub_keys = vec![[zero.clone(), zero.clone()]; batch_size];
    enc_pub_keys[0] = enc_pub_key;
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

    let mut current_state_leaves = vec![zero_state_leaf.clone(); batch_size];
    current_state_leaves[0] = state_leaf;
    let mut current_state_paths = vec![empty_state_path; batch_size];
    current_state_paths[0] = valid_state_path;

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
        current_vote_weights: vec![zero.clone(); batch_size],
        current_vote_weights_path_elements: vec![vote_path; batch_size],
    })
}

#[cfg(feature = "zkvm-native-crypto")]
fn quin_root_and_path(
    leaves: &[Field],
    depth: usize,
    index: usize,
) -> ProofResult<(Field, Vec<Vec<Field>>)> {
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
        let mut siblings = Vec::with_capacity(4);
        for child in 0..5 {
            if child != child_index {
                siblings.push(level[group_start + child].clone());
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

fn zero_sibling_path(depth: usize) -> ProofResult<Vec<Vec<Field>>> {
    let mut path = Vec::with_capacity(depth);
    for level in 0..depth {
        path.push(vec![zero_root(level)?; 4]);
    }
    Ok(path)
}

#[cfg(feature = "zkvm-native-crypto")]
fn pack_command_data(
    poll_id: &BigUint,
    vote_weight_high: &BigUint,
    vote_weight_mid: &BigUint,
    vote_weight_low: &BigUint,
    vote_option_index: &BigUint,
    state_index: &BigUint,
    nonce: &BigUint,
) -> BigUint {
    (poll_id << 192usize)
        + (vote_weight_high << 160usize)
        + (vote_weight_mid << 128usize)
        + (vote_weight_low << 96usize)
        + (vote_option_index << 64usize)
        + (state_index << 32usize)
        + nonce
}
