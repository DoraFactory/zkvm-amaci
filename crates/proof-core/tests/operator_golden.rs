#![cfg(not(feature = "zkvm-native-crypto"))]

use amaci_proof_core::{
    execute_proof_logic, AddNewKeyInput, ProcessDeactivateInput, ProcessMessagesInput, ProofError,
    ProverInput, PublicOutput, TallyVotesInput,
};
use maci_crypto::{compute_input_hash, poseidon};
use num_bigint::BigUint;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(path)
}

fn load_json(path: &str) -> Value {
    let path = repo_path(path);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn field(value: &Value) -> BigUint {
    match value {
        Value::String(s) => s.parse().unwrap(),
        Value::Number(n) => BigUint::from(n.as_u64().unwrap()),
        _ => panic!("expected field string/number, got {value:?}"),
    }
}

fn fields(value: &Value) -> Vec<BigUint> {
    value.as_array().unwrap().iter().map(field).collect()
}

fn matrix(value: &Value) -> Vec<Vec<BigUint>> {
    value.as_array().unwrap().iter().map(fields).collect()
}

fn paths(value: &Value) -> Vec<Vec<Vec<BigUint>>> {
    value.as_array().unwrap().iter().map(matrix).collect()
}

fn pub_keys(value: &Value) -> Vec<[BigUint; 2]> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let values = fields(v);
            [values[0].clone(), values[1].clone()]
        })
        .collect()
}

fn pub_key(value: &Value) -> [BigUint; 2] {
    let values = fields(value);
    [values[0].clone(), values[1].clone()]
}

fn log5(value: usize) -> usize {
    let mut power = 1usize;
    let mut depth = 0usize;
    while power < value {
        power *= 5;
        depth += 1;
    }
    assert_eq!(power, value, "{value} is not a power of 5");
    depth
}

fn process_messages_input(value: &Value) -> ProcessMessagesInput {
    let msgs = matrix(&value["msgs"]);
    let current_state_leaves_path_elements = paths(&value["currentStateLeavesPathElements"]);
    let current_vote_weights_path_elements = paths(&value["currentVoteWeightsPathElements"]);
    ProcessMessagesInput {
        state_tree_depth: current_state_leaves_path_elements[0].len(),
        vote_option_tree_depth: current_vote_weights_path_elements[0].len(),
        batch_size: msgs.len(),
        input_hash: field(&value["inputHash"]),
        packed_vals: field(&value["packedVals"]),
        expected_poll_id: field(&value["expectedPollId"]),
        batch_start_hash: field(&value["batchStartHash"]),
        batch_end_hash: field(&value["batchEndHash"]),
        coord_priv_key: field(&value["coordPrivKey"]),
        coord_pub_key: pub_key(&value["coordPubKey"]),
        msgs,
        enc_pub_keys: pub_keys(&value["encPubKeys"]),
        current_state_root: field(&value["currentStateRoot"]),
        current_state_leaves: matrix(&value["currentStateLeaves"]),
        current_state_leaves_path_elements,
        current_state_commitment: field(&value["currentStateCommitment"]),
        current_state_salt: field(&value["currentStateSalt"]),
        new_state_commitment: field(&value["newStateCommitment"]),
        new_state_salt: field(&value["newStateSalt"]),
        active_state_root: field(&value["activeStateRoot"]),
        deactivate_root: field(&value["deactivateRoot"]),
        deactivate_commitment: field(&value["deactivateCommitment"]),
        active_state_leaves: fields(&value["activeStateLeaves"]),
        active_state_leaves_path_elements: paths(&value["activeStateLeavesPathElements"]),
        current_vote_weights: fields(&value["currentVoteWeights"]),
        current_vote_weights_path_elements,
    }
}

fn tally_votes_input(value: &Value) -> TallyVotesInput {
    let state_leaf = matrix(&value["stateLeaf"]);
    let state_path_elements = matrix(&value["statePathElements"]);
    let votes = matrix(&value["votes"]);
    let int_state_tree_depth = log5(state_leaf.len());
    TallyVotesInput {
        state_tree_depth: int_state_tree_depth + state_path_elements.len(),
        int_state_tree_depth,
        vote_option_tree_depth: log5(votes[0].len()),
        input_hash: field(&value["inputHash"]),
        packed_vals: field(&value["packedVals"]),
        state_root: field(&value["stateRoot"]),
        state_salt: field(&value["stateSalt"]),
        state_commitment: field(&value["stateCommitment"]),
        current_tally_commitment: field(&value["currentTallyCommitment"]),
        new_tally_commitment: field(&value["newTallyCommitment"]),
        state_leaf,
        state_path_elements,
        votes,
        current_results: fields(&value["currentResults"]),
        current_results_root_salt: field(&value["currentResultsRootSalt"]),
        new_results_root_salt: field(&value["newResultsRootSalt"]),
    }
}

fn process_deactivate_input(value: &Value, state_tree_depth: usize) -> ProcessDeactivateInput {
    let msgs = matrix(&value["msgs"]);
    ProcessDeactivateInput {
        state_tree_depth,
        batch_size: msgs.len(),
        input_hash: field(&value["inputHash"]),
        expected_poll_id: field(&value["expectedPollId"]),
        current_active_state_root: field(&value["currentActiveStateRoot"]),
        current_deactivate_root: field(&value["currentDeactivateRoot"]),
        batch_start_hash: field(&value["batchStartHash"]),
        batch_end_hash: field(&value["batchEndHash"]),
        coord_priv_key: field(&value["coordPrivKey"]),
        coord_pub_key: pub_key(&value["coordPubKey"]),
        msgs,
        enc_pub_keys: pub_keys(&value["encPubKeys"]),
        c1: pub_keys(&value["c1"]),
        c2: pub_keys(&value["c2"]),
        current_active_state: fields(&value["currentActiveState"]),
        new_active_state: fields(&value["newActiveState"]),
        deactivate_index0: field(&value["deactivateIndex0"]),
        current_state_root: field(&value["currentStateRoot"]),
        current_state_leaves: matrix(&value["currentStateLeaves"]),
        current_state_leaves_path_elements: paths(&value["currentStateLeavesPathElements"]),
        active_state_leaves_path_elements: paths(&value["activeStateLeavesPathElements"]),
        deactivate_leaves_path_elements: paths(&value["deactivateLeavesPathElements"]),
        current_deactivate_commitment: field(&value["currentDeactivateCommitment"]),
        new_deactivate_root: field(&value["newDeactivateRoot"]),
        new_deactivate_commitment: field(&value["newDeactivateCommitment"]),
    }
}

fn add_new_key_input(value: &Value, state_tree_depth: usize) -> AddNewKeyInput {
    AddNewKeyInput {
        state_tree_depth,
        input_hash: field(&value["inputHash"]),
        coord_pub_key: pub_key(&value["coordPubKey"]),
        deactivate_root: field(&value["deactivateRoot"]),
        deactivate_index: field(&value["deactivateIndex"]),
        deactivate_leaf: field(&value["deactivateLeaf"]),
        c1: pub_key(&value["c1"]),
        c2: pub_key(&value["c2"]),
        random_val: field(&value["randomVal"]),
        d1: pub_key(&value["d1"]),
        d2: pub_key(&value["d2"]),
        deactivate_leaf_path_elements: matrix(&value["deactivateLeafPathElements"]),
        nullifier: field(&value["nullifier"]),
        old_private_key: field(&value["oldPrivateKey"]),
        new_pub_key: pub_key(&value["newPubKey"]),
        poll_id: field(&value["pollId"]),
    }
}

fn valid_process_messages_input() -> ProcessMessagesInput {
    let raw = load_json(
        "amaci-operator/test-data/data/dora10sfhzqa0dfwxc36y94k7wce20rjkvavr5w4e2pdxvnwruv6ahj9qkrjfkt/inputs/msg/000000.json",
    );
    process_messages_input(&raw)
}

fn valid_tally_votes_input() -> TallyVotesInput {
    let raw = load_json(
        "amaci-operator/test-data/data/dora10sfhzqa0dfwxc36y94k7wce20rjkvavr5w4e2pdxvnwruv6ahj9qkrjfkt/inputs/tally/000000.json",
    );
    tally_votes_input(&raw)
}

fn valid_process_deactivate_input() -> ProcessDeactivateInput {
    let raw = load_json("zkvm-amaci/tests/golden/process_deactivate_2_5_valid.json");
    process_deactivate_input(&raw["input"], 2)
}

fn valid_add_new_key_input() -> AddNewKeyInput {
    let raw = load_json("zkvm-amaci/tests/golden/add_new_key_2_valid.json");
    add_new_key_input(&raw["input"], 2)
}

fn bump(value: &mut BigUint) {
    *value += BigUint::from(1u32);
}

fn err(input: ProverInput) -> ProofError {
    execute_proof_logic(&input).expect_err("mutated fixture should fail")
}

fn assert_input_hash_mismatch(error: ProofError) {
    assert!(
        matches!(error, ProofError::InputHashMismatch { .. }),
        "expected input hash mismatch, got {error:?}"
    );
}

fn assert_commitment_mismatch(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::CommitmentMismatch { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected commitment mismatch for {expected_name}, got {other:?}"),
    }
}

fn assert_merkle_mismatch(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::MerkleRootMismatch { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected Merkle mismatch for {expected_name}, got {other:?}"),
    }
}

fn assert_invalid_length(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::InvalidLength { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected invalid length for {expected_name}, got {other:?}"),
    }
}

fn assert_invalid_range(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::InvalidRange { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected invalid range for {expected_name}, got {other:?}"),
    }
}

fn assert_invalid_boolean(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::InvalidBoolean { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected invalid boolean for {expected_name}, got {other:?}"),
    }
}

fn recompute_process_deactivate_input_hash(input: &mut ProcessDeactivateInput) {
    let coord_hash = poseidon(&input.coord_pub_key);
    input.input_hash = compute_input_hash(&[
        input.new_deactivate_root.clone(),
        coord_hash,
        input.batch_start_hash.clone(),
        input.batch_end_hash.clone(),
        input.current_deactivate_commitment.clone(),
        input.new_deactivate_commitment.clone(),
        input.current_state_root.clone(),
        input.expected_poll_id.clone(),
    ]);
}

#[test]
fn operator_process_messages_fixture_matches_public_output() {
    let input = valid_process_messages_input();
    let expected_input_hash = input.input_hash.clone();
    let expected_new_state_commitment = input.new_state_commitment.clone();

    let output = execute_proof_logic(&ProverInput::ProcessMessages(input)).unwrap();
    let PublicOutput::ProcessMessages(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, expected_input_hash);
    assert_eq!(output.new_state_commitment, expected_new_state_commitment);
}

#[test]
fn operator_tally_votes_fixture_matches_public_output() {
    let input = valid_tally_votes_input();
    let expected_input_hash = input.input_hash.clone();
    let expected_new_tally_commitment = input.new_tally_commitment.clone();

    let output = execute_proof_logic(&ProverInput::TallyVotes(input)).unwrap();
    let PublicOutput::TallyVotes(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, expected_input_hash);
    assert_eq!(output.new_tally_commitment, expected_new_tally_commitment);
}

#[test]
fn generated_process_deactivate_fixture_matches_public_output() {
    let input = valid_process_deactivate_input();
    let expected_input_hash = input.input_hash.clone();
    let expected_new_deactivate_root = input.new_deactivate_root.clone();
    let expected_new_deactivate_commitment = input.new_deactivate_commitment.clone();

    let output = execute_proof_logic(&ProverInput::ProcessDeactivate(input)).unwrap();
    let PublicOutput::ProcessDeactivate(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, expected_input_hash);
    assert_eq!(output.new_deactivate_root, expected_new_deactivate_root);
    assert_eq!(
        output.new_deactivate_commitment,
        expected_new_deactivate_commitment
    );
}

#[test]
fn generated_add_new_key_fixture_matches_public_output() {
    let input = valid_add_new_key_input();
    let expected_input_hash = input.input_hash.clone();
    let expected_nullifier = input.nullifier.clone();
    let expected_d1 = input.d1.clone();
    let expected_d2 = input.d2.clone();

    let output = execute_proof_logic(&ProverInput::AddNewKey(input)).unwrap();
    let PublicOutput::AddNewKey(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, expected_input_hash);
    assert_eq!(output.nullifier, expected_nullifier);
    assert_eq!(output.d1, expected_d1);
    assert_eq!(output.d2, expected_d2);
}

#[test]
fn process_messages_rejects_mutated_public_input_hash() {
    let mut input = valid_process_messages_input();
    bump(&mut input.input_hash);
    assert_input_hash_mismatch(err(ProverInput::ProcessMessages(input)));
}

#[test]
fn process_messages_rejects_current_state_commitment_mismatch() {
    let mut input = valid_process_messages_input();
    bump(&mut input.current_state_commitment);
    assert_commitment_mismatch(
        err(ProverInput::ProcessMessages(input)),
        "currentStateCommitment",
    );
}

#[test]
fn process_messages_rejects_deactivate_commitment_mismatch() {
    let mut input = valid_process_messages_input();
    bump(&mut input.deactivate_commitment);
    assert_commitment_mismatch(
        err(ProverInput::ProcessMessages(input)),
        "deactivateCommitment",
    );
}

#[test]
fn process_messages_rejects_message_hash_chain_mismatch() {
    let mut input = valid_process_messages_input();
    bump(&mut input.batch_end_hash);
    assert!(
        matches!(
            err(ProverInput::ProcessMessages(input)),
            ProofError::MessageHashChainMismatch { .. }
        ),
        "expected message hash chain mismatch"
    );
}

#[test]
fn process_messages_rejects_bad_state_leaf_path() {
    let mut input = valid_process_messages_input();
    bump(&mut input.current_state_leaves_path_elements[0][0][0]);
    assert_merkle_mismatch(
        err(ProverInput::ProcessMessages(input)),
        "process state leaf",
    );
}

#[test]
fn process_messages_rejects_new_state_commitment_mismatch() {
    let mut input = valid_process_messages_input();
    bump(&mut input.new_state_salt);
    assert_commitment_mismatch(
        err(ProverInput::ProcessMessages(input)),
        "newStateCommitment",
    );
}

#[test]
fn process_messages_rejects_invalid_quadratic_cost_flag() {
    let mut input = valid_process_messages_input();
    let low_64_bits = BigUint::from(1u32) << 64usize;
    input.packed_vals = (&input.packed_vals % &low_64_bits) + (BigUint::from(2u32) << 64usize);
    assert_invalid_boolean(err(ProverInput::ProcessMessages(input)), "isQuadraticCost");
}

#[test]
fn process_messages_rejects_batch_length_mismatch() {
    let mut input = valid_process_messages_input();
    input.msgs.pop();
    assert_invalid_length(err(ProverInput::ProcessMessages(input)), "msgs");
}

#[test]
fn tally_votes_rejects_mutated_public_input_hash() {
    let mut input = valid_tally_votes_input();
    bump(&mut input.input_hash);
    assert_input_hash_mismatch(err(ProverInput::TallyVotes(input)));
}

#[test]
fn tally_votes_rejects_state_commitment_mismatch() {
    let mut input = valid_tally_votes_input();
    bump(&mut input.state_commitment);
    assert_commitment_mismatch(err(ProverInput::TallyVotes(input)), "stateCommitment");
}

#[test]
fn tally_votes_rejects_state_subtree_path_mismatch() {
    let mut input = valid_tally_votes_input();
    bump(&mut input.state_path_elements[0][0]);
    assert_merkle_mismatch(err(ProverInput::TallyVotes(input)), "state subtree");
}

#[test]
fn tally_votes_rejects_vote_option_root_mismatch() {
    let mut input = valid_tally_votes_input();
    bump(&mut input.votes[0][0]);
    assert_merkle_mismatch(err(ProverInput::TallyVotes(input)), "vote option root");
}

#[test]
fn tally_votes_rejects_current_tally_commitment_mismatch() {
    let mut input = valid_tally_votes_input();
    bump(&mut input.current_tally_commitment);
    assert_commitment_mismatch(
        err(ProverInput::TallyVotes(input)),
        "currentTallyCommitment",
    );
}

#[test]
fn tally_votes_rejects_new_tally_commitment_mismatch() {
    let mut input = valid_tally_votes_input();
    bump(&mut input.new_results_root_salt);
    assert_commitment_mismatch(err(ProverInput::TallyVotes(input)), "newTallyCommitment");
}

#[test]
fn tally_votes_rejects_invalid_internal_tree_depth() {
    let mut input = valid_tally_votes_input();
    input.int_state_tree_depth = input.state_tree_depth;
    assert_invalid_range(err(ProverInput::TallyVotes(input)), "intStateTreeDepth");
}

#[test]
fn tally_votes_rejects_result_length_mismatch() {
    let mut input = valid_tally_votes_input();
    input.current_results.pop();
    assert_invalid_length(err(ProverInput::TallyVotes(input)), "currentResults");
}

#[test]
fn process_deactivate_rejects_mutated_public_input_hash() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.input_hash);
    assert_input_hash_mismatch(err(ProverInput::ProcessDeactivate(input)));
}

#[test]
fn process_deactivate_rejects_current_commitment_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.current_deactivate_commitment);
    assert_commitment_mismatch(
        err(ProverInput::ProcessDeactivate(input)),
        "currentDeactivateCommitment",
    );
}

#[test]
fn process_deactivate_rejects_coord_pub_key_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.coord_pub_key[0]);
    assert_commitment_mismatch(err(ProverInput::ProcessDeactivate(input)), "coordPubKey");
}

#[test]
fn process_deactivate_rejects_message_hash_chain_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.batch_end_hash);
    assert!(
        matches!(
            err(ProverInput::ProcessDeactivate(input)),
            ProofError::MessageHashChainMismatch { .. }
        ),
        "expected message hash chain mismatch"
    );
}

#[test]
fn process_deactivate_rejects_state_leaf_path_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.current_state_leaves_path_elements[0][0][0]);
    assert_merkle_mismatch(
        err(ProverInput::ProcessDeactivate(input)),
        "deactivate state leaf",
    );
}

#[test]
fn process_deactivate_rejects_active_state_path_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.active_state_leaves_path_elements[0][0][0]);
    assert_merkle_mismatch(
        err(ProverInput::ProcessDeactivate(input)),
        "current active state",
    );
}

#[test]
fn process_deactivate_rejects_deactivate_zero_leaf_path_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.deactivate_leaves_path_elements[0][0][0]);
    assert_merkle_mismatch(
        err(ProverInput::ProcessDeactivate(input)),
        "current deactivate zero leaf",
    );
}

#[test]
fn process_deactivate_rejects_new_deactivate_commitment_mismatch() {
    let mut input = valid_process_deactivate_input();
    bump(&mut input.new_deactivate_commitment);
    recompute_process_deactivate_input_hash(&mut input);
    assert_commitment_mismatch(
        err(ProverInput::ProcessDeactivate(input)),
        "newDeactivateCommitment",
    );
}

#[test]
fn process_deactivate_rejects_batch_length_mismatch() {
    let mut input = valid_process_deactivate_input();
    input.c1.pop();
    assert_invalid_length(err(ProverInput::ProcessDeactivate(input)), "c1");
}

#[test]
fn add_new_key_rejects_mutated_public_input_hash() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.input_hash);
    assert_input_hash_mismatch(err(ProverInput::AddNewKey(input)));
}

#[test]
fn add_new_key_rejects_nullifier_mismatch() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.nullifier);
    assert_commitment_mismatch(err(ProverInput::AddNewKey(input)), "nullifier");
}

#[test]
fn add_new_key_rejects_deactivate_leaf_mismatch() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.deactivate_leaf);
    assert_commitment_mismatch(err(ProverInput::AddNewKey(input)), "deactivateLeaf");
}

#[test]
fn add_new_key_rejects_deactivate_leaf_path_mismatch() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.deactivate_leaf_path_elements[0][0]);
    assert_merkle_mismatch(err(ProverInput::AddNewKey(input)), "deactivate leaf");
}

#[test]
fn add_new_key_rejects_d1_mismatch() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.d1[0]);
    assert_commitment_mismatch(err(ProverInput::AddNewKey(input)), "d1");
}

#[test]
fn add_new_key_rejects_d2_mismatch() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.d2[0]);
    assert_commitment_mismatch(err(ProverInput::AddNewKey(input)), "d2");
}

#[test]
fn add_new_key_rejects_new_pub_key_hash_mismatch_in_public_input() {
    let mut input = valid_add_new_key_input();
    bump(&mut input.new_pub_key[0]);
    assert_input_hash_mismatch(err(ProverInput::AddNewKey(input)));
}
