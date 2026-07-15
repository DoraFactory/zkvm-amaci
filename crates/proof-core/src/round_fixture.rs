use crate::auth::{
    auth_keypair_from_seed_for_testing, auth_public_key_hash, sign_command_for_testing,
};
use crate::circuits::process_messages::{message_chain, EmptyRule};
use crate::crypto::{
    native_encrypt_for_testing, native_rerandomize_ciphertext, private_to_pub_key,
};
use crate::error::ProofResult;
use crate::field::Field;
use crate::hash_backend::{hash_fields, hash_pair, hash_public_inputs, hash_state_leaf};
use crate::merkle::{hash5_exact, zero_root};
use crate::types::{
    AddNewKeyInput, KemCiphertext, KemPublicKey, Message, PathElement, PathElements,
    ProcessDeactivateInput, ProcessMessagesInput, ProverInput, PubKey, StateLeaf, TallyVotesInput,
    VoteRow, VOTE_ROW_WORDS,
};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

pub const FIVE_SIGNUP_ROUND_ID: &str = "five-signup-2-1-1-5";
pub const FIFTEEN_SIGNUP_ROUND_ID: &str = "fifteen-signup-15-message-2-1-1-5";
pub const FIFTY_SIGNUP_ROUND_ID: &str = "fifty-signup-50-message-3-1-1-5";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStageInput {
    pub name: String,
    pub stage: String,
    pub input: ProverInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveSignupRoundFixture {
    pub round_id: String,
    pub state_tree_depth: usize,
    pub vote_option_tree_depth: usize,
    pub process_message_batch_size: usize,
    pub tally_batch_size: usize,
    pub initial_signups: usize,
    pub final_signups: usize,
    pub deactivate_state_indices: Vec<u32>,
    pub add_new_key_old_state_index: u32,
    pub add_new_key_new_state_index: u32,
    pub votes: Vec<RoundVote>,
    pub expected_raw_results: [u128; VOTE_ROW_WORDS],
    pub stages: Vec<RoundStageInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupRoundFixture {
    pub round_id: String,
    pub state_tree_depth: usize,
    pub vote_option_tree_depth: usize,
    pub process_message_batch_size: usize,
    pub tally_batch_size: usize,
    pub initial_signups: usize,
    pub final_signups: usize,
    pub message_count: usize,
    pub deactivate_state_indices: Vec<u32>,
    pub add_new_key_old_state_index: u32,
    pub add_new_key_new_state_index: u32,
    pub votes: Vec<RoundVote>,
    pub expected_raw_results: [u128; VOTE_ROW_WORDS],
    pub stages: Vec<RoundStageInput>,
}

pub type FifteenSignupRoundFixture = SignupRoundFixture;
pub type FiftySignupRoundFixture = SignupRoundFixture;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundVote {
    pub state_index: u32,
    pub vote_option_index: u32,
    pub new_vote_weight: u32,
    pub expected_valid: bool,
    pub note: String,
}

#[derive(Clone)]
struct User {
    priv_key: Field,
    pub_key: PubKey,
    kem_pub_key: KemPublicKey,
    auth_pub_key: Vec<u8>,
    balance: Field,
    nonce: Field,
    votes: VoteRow,
}

impl User {
    fn new(priv_key: u32, balance: u32) -> Self {
        let priv_key = Field::from(priv_key);
        let (auth_pub_key, _) = auth_keypair_from_seed_for_testing(&priv_key);
        let kem_pub_key = crate::pq_kem::kem_public_key_from_seed_for_testing(&priv_key);
        Self {
            pub_key: private_to_pub_key(&priv_key),
            kem_pub_key,
            auth_pub_key,
            priv_key,
            balance: Field::from(balance),
            nonce: Field::from(0u32),
            votes: [Field::from(0u32); VOTE_ROW_WORDS],
        }
    }

    fn state_leaf(&self) -> ProofResult<StateLeaf> {
        Ok([
            self.pub_key[0].clone(),
            self.pub_key[1].clone(),
            self.balance.clone(),
            vote_root(&self.votes)?,
            self.nonce.clone(),
            Field::from(0u32),
            Field::from(0u32),
            Field::from(0u32),
            Field::from(0u32),
            auth_public_key_hash(&self.auth_pub_key),
        ])
    }
}

#[derive(Clone)]
struct VoteCommand {
    state_index: usize,
    vote_option_index: usize,
    new_vote_weight: u32,
    valid: bool,
    user_priv_key: Field,
    new_pub_key: PubKey,
}

pub fn five_signup_round_fixture() -> ProofResult<FiveSignupRoundFixture> {
    let state_tree_depth = 2;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let poll_id = Field::from(1u32);
    let coord_priv_key = Field::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let state_tree_size = 5usize.pow(state_tree_depth as u32);
    let deactivate_tree_depth = state_tree_depth + 2;
    let deactivate_tree_size = 5usize.pow(deactivate_tree_depth as u32);
    let deactivate_index0 = 17usize;

    let mut users = vec![
        User::new(6001, 20),
        User::new(6002, 20),
        User::new(6003, 20),
        User::new(6004, 20),
        User::new(6005, 20),
    ];
    let replacement = User::new(9001, 20);

    let zero_state_leaf = [Field::from(0u32); 10];
    let zero_state_leaf_hash = hash_state_leaf(&zero_state_leaf)?;
    let mut state_hashes = vec![zero_state_leaf_hash; state_tree_size];
    for (idx, user) in users.iter().enumerate() {
        state_hashes[idx] = hash_state_leaf(&user.state_leaf()?)?;
    }
    let mut state_tree = QuinTree::new(state_hashes, state_tree_depth)?;

    let mut active_tree = QuinTree::zeros(state_tree_size, state_tree_depth)?;
    let mut deactivate_tree = QuinTree::zeros(deactivate_tree_size, deactivate_tree_depth)?;

    let process_deactivate = build_process_deactivate(
        &coord_priv_key,
        &coord_pub_key,
        &poll_id,
        &state_tree,
        &mut active_tree,
        &mut deactivate_tree,
        &users,
        [3, 4],
        deactivate_index0,
    )?;

    let add_new_key = build_add_new_key(
        state_tree_depth,
        &coord_pub_key,
        &poll_id,
        &users[4],
        &replacement,
        &deactivate_tree,
        deactivate_index0 + 1,
        1,
    )?;

    users.push(replacement);
    state_tree.set(5, hash_state_leaf(&users[5].state_leaf()?)?)?;

    let message_commands = vec![
        VoteCommand {
            state_index: 3,
            vote_option_index: 1,
            new_vote_weight: 1,
            valid: false,
            user_priv_key: users[3].priv_key.clone(),
            new_pub_key: users[3].pub_key.clone(),
        },
        VoteCommand {
            state_index: 4,
            vote_option_index: 2,
            new_vote_weight: 2,
            valid: false,
            user_priv_key: users[4].priv_key.clone(),
            new_pub_key: users[4].pub_key.clone(),
        },
        VoteCommand {
            state_index: 0,
            vote_option_index: 0,
            new_vote_weight: 1,
            valid: true,
            user_priv_key: users[0].priv_key.clone(),
            new_pub_key: users[0].pub_key.clone(),
        },
        VoteCommand {
            state_index: 5,
            vote_option_index: 4,
            new_vote_weight: 5,
            valid: true,
            user_priv_key: users[5].priv_key.clone(),
            new_pub_key: users[5].pub_key.clone(),
        },
        VoteCommand {
            state_index: 0,
            vote_option_index: 4,
            new_vote_weight: 5,
            valid: true,
            user_priv_key: users[0].priv_key.clone(),
            new_pub_key: users[0].pub_key.clone(),
        },
    ];
    let process_messages_full = build_process_messages_batch(
        &coord_priv_key,
        &coord_pub_key,
        &poll_id,
        batch_size,
        6,
        Field::from(0u32),
        Field::from(31u32),
        Field::from(33u32),
        &active_tree,
        &deactivate_tree,
        &mut state_tree,
        &mut users,
        &message_commands,
    )?;

    let tally_0_rows = [
        users[0].votes,
        users[1].votes,
        users[2].votes,
        users[3].votes,
        users[4].votes,
    ];
    let tally_0 = build_tally_batch(
        state_tree_depth,
        1,
        vote_option_tree_depth,
        6,
        0,
        &state_tree,
        &users,
        &Field::from(33u32),
        &[],
        &Field::from(0u32),
        &Field::from(41u32),
    )?;
    let results_after_tally0 =
        tally_encoded_results(&vec![Field::from(0u32); VOTE_ROW_WORDS], &tally_0_rows);
    let tally_1 = build_tally_batch(
        state_tree_depth,
        1,
        vote_option_tree_depth,
        6,
        1,
        &state_tree,
        &users,
        &Field::from(33u32),
        &results_after_tally0,
        &Field::from(41u32),
        &Field::from(42u32),
    )?;

    Ok(FiveSignupRoundFixture {
        round_id: FIVE_SIGNUP_ROUND_ID.to_string(),
        state_tree_depth,
        vote_option_tree_depth,
        process_message_batch_size: batch_size,
        tally_batch_size: batch_size,
        initial_signups: 5,
        final_signups: 6,
        deactivate_state_indices: vec![3, 4],
        add_new_key_old_state_index: 4,
        add_new_key_new_state_index: 5,
        votes: vec![
            RoundVote {
                state_index: 0,
                vote_option_index: 0,
                new_vote_weight: 1,
                expected_valid: true,
                note: "initial key vote".to_string(),
            },
            RoundVote {
                state_index: 0,
                vote_option_index: 4,
                new_vote_weight: 5,
                expected_valid: true,
                note: "same voter second option".to_string(),
            },
            RoundVote {
                state_index: 3,
                vote_option_index: 1,
                new_vote_weight: 1,
                expected_valid: false,
                note: "old key after deactivate".to_string(),
            },
            RoundVote {
                state_index: 4,
                vote_option_index: 2,
                new_vote_weight: 2,
                expected_valid: false,
                note: "old key after deactivate and addNewKey".to_string(),
            },
            RoundVote {
                state_index: 5,
                vote_option_index: 4,
                new_vote_weight: 5,
                expected_valid: true,
                note: "new key vote".to_string(),
            },
        ],
        expected_raw_results: [1, 0, 0, 0, 10],
        stages: vec![
            RoundStageInput {
                name: "five-signup-process-deactivate".to_string(),
                stage: "process_deactivate".to_string(),
                input: ProverInput::ProcessDeactivate(process_deactivate),
            },
            RoundStageInput {
                name: "five-signup-add-new-key".to_string(),
                stage: "add_new_key".to_string(),
                input: ProverInput::AddNewKey(add_new_key),
            },
            RoundStageInput {
                name: "five-signup-process-messages-full".to_string(),
                stage: "process_messages".to_string(),
                input: ProverInput::ProcessMessages(process_messages_full),
            },
            RoundStageInput {
                name: "five-signup-tally-0".to_string(),
                stage: "tally".to_string(),
                input: ProverInput::TallyVotes(tally_0),
            },
            RoundStageInput {
                name: "five-signup-tally-1".to_string(),
                stage: "tally".to_string(),
                input: ProverInput::TallyVotes(tally_1),
            },
        ],
    })
}

pub fn fifteen_signup_round_fixture() -> ProofResult<FifteenSignupRoundFixture> {
    build_signup_round_fixture(ScaledRoundConfig {
        round_id: FIFTEEN_SIGNUP_ROUND_ID,
        stage_prefix: "fifteen-signup",
        state_tree_depth: 2,
        initial_signups: 15,
        user_private_key_start: 7001,
        replacement_private_key: 9001,
    })
}

pub fn fifty_signup_round_fixture() -> ProofResult<FiftySignupRoundFixture> {
    build_signup_round_fixture(ScaledRoundConfig {
        round_id: FIFTY_SIGNUP_ROUND_ID,
        stage_prefix: "fifty-signup",
        state_tree_depth: 3,
        initial_signups: 50,
        user_private_key_start: 10_001,
        replacement_private_key: 20_001,
    })
}

struct ScaledRoundConfig {
    round_id: &'static str,
    stage_prefix: &'static str,
    state_tree_depth: usize,
    initial_signups: usize,
    user_private_key_start: u32,
    replacement_private_key: u32,
}

fn build_signup_round_fixture(config: ScaledRoundConfig) -> ProofResult<SignupRoundFixture> {
    let state_tree_depth = config.state_tree_depth;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let initial_signups = config.initial_signups;
    let final_signups = initial_signups + 1;
    if initial_signups < 3 || initial_signups % batch_size != 0 {
        return Err(crate::ProofError::Crypto(
            "scaled round requires a signup count divisible by five and at least three".to_string(),
        ));
    }
    let poll_id = Field::from(1u32);
    let coord_priv_key = Field::from(1001u32);
    let coord_pub_key = private_to_pub_key(&coord_priv_key);
    let state_tree_size = 5usize.pow(state_tree_depth as u32);
    if final_signups > state_tree_size {
        return Err(crate::ProofError::InvalidLength {
            name: "scaled round state leaves",
            expected: state_tree_size,
            actual: final_signups,
        });
    }
    let deactivate_tree_depth = state_tree_depth + 2;
    let deactivate_tree_size = 5usize.pow(deactivate_tree_depth as u32);
    let deactivate_index0 = initial_signups * 3 + 2;
    let deactivate_state_indices = [initial_signups - 2, initial_signups - 1];

    let mut users = (0..initial_signups)
        .map(|idx| User::new(config.user_private_key_start + idx as u32, 20))
        .collect::<Vec<_>>();
    let replacement = User::new(config.replacement_private_key, 20);

    let zero_state_leaf = [Field::from(0u32); 10];
    let zero_state_leaf_hash = hash_state_leaf(&zero_state_leaf)?;
    let mut state_hashes = vec![zero_state_leaf_hash; state_tree_size];
    for (idx, user) in users.iter().enumerate() {
        state_hashes[idx] = hash_state_leaf(&user.state_leaf()?)?;
    }
    let mut state_tree = QuinTree::new(state_hashes, state_tree_depth)?;
    let mut active_tree = QuinTree::zeros(state_tree_size, state_tree_depth)?;
    let mut deactivate_tree = QuinTree::zeros(deactivate_tree_size, deactivate_tree_depth)?;

    let process_deactivate = build_process_deactivate(
        &coord_priv_key,
        &coord_pub_key,
        &poll_id,
        &state_tree,
        &mut active_tree,
        &mut deactivate_tree,
        &users,
        deactivate_state_indices,
        deactivate_index0,
    )?;
    let add_new_key = build_add_new_key(
        state_tree_depth,
        &coord_pub_key,
        &poll_id,
        &users[deactivate_state_indices[1]],
        &replacement,
        &deactivate_tree,
        deactivate_index0 + 1,
        1,
    )?;

    users.push(replacement);
    state_tree.set(
        initial_signups,
        hash_state_leaf(&users[initial_signups].state_leaf()?)?,
    )?;

    let mut message_commands = Vec::with_capacity(initial_signups);
    message_commands.push(VoteCommand {
        state_index: deactivate_state_indices[0],
        vote_option_index: 1,
        new_vote_weight: 2,
        valid: false,
        user_priv_key: users[deactivate_state_indices[0]].priv_key,
        new_pub_key: users[deactivate_state_indices[0]].pub_key,
    });
    message_commands.push(VoteCommand {
        state_index: deactivate_state_indices[1],
        vote_option_index: 2,
        new_vote_weight: 3,
        valid: false,
        user_priv_key: users[deactivate_state_indices[1]].priv_key,
        new_pub_key: users[deactivate_state_indices[1]].pub_key,
    });
    for state_index in 0..initial_signups - 3 {
        let vote_option_index = state_index % VOTE_ROW_WORDS;
        message_commands.push(VoteCommand {
            state_index,
            vote_option_index,
            new_vote_weight: vote_option_index as u32 + 1,
            valid: true,
            user_priv_key: users[state_index].priv_key,
            new_pub_key: users[state_index].pub_key,
        });
    }
    message_commands.push(VoteCommand {
        state_index: initial_signups,
        vote_option_index: 4,
        new_vote_weight: 5,
        valid: true,
        user_priv_key: users[initial_signups].priv_key,
        new_pub_key: users[initial_signups].pub_key,
    });
    debug_assert_eq!(message_commands.len(), initial_signups);

    let mut stages = vec![
        RoundStageInput {
            name: format!("{}-process-deactivate", config.stage_prefix),
            stage: "process_deactivate".to_string(),
            input: ProverInput::ProcessDeactivate(process_deactivate),
        },
        RoundStageInput {
            name: format!("{}-add-new-key", config.stage_prefix),
            stage: "add_new_key".to_string(),
            input: ProverInput::AddNewKey(add_new_key),
        },
    ];

    let message_batch_count = message_commands.len() / batch_size;
    let mut batch_start_hash = Field::from(0u32);
    for batch_num in 0..message_batch_count {
        let input = build_process_messages_batch(
            &coord_priv_key,
            &coord_pub_key,
            &poll_id,
            batch_size,
            final_signups as u32,
            batch_start_hash,
            Field::from(30u32 + batch_num as u32),
            Field::from(31u32 + batch_num as u32),
            &active_tree,
            &deactivate_tree,
            &mut state_tree,
            &mut users,
            &message_commands[batch_num * batch_size..(batch_num + 1) * batch_size],
        )?;
        batch_start_hash = input.batch_end_hash.clone();
        stages.push(RoundStageInput {
            name: format!("{}-process-messages-{batch_num}", config.stage_prefix),
            stage: "process_messages".to_string(),
            input: ProverInput::ProcessMessages(input),
        });
    }

    let mut current_results = vec![Field::from(0u32); VOTE_ROW_WORDS];
    let mut current_results_root_salt = Field::from(0u32);
    let final_state_salt = Field::from(30u32 + message_batch_count as u32);
    for batch_num in 0..final_signups.div_ceil(batch_size) {
        let new_results_root_salt = Field::from(41u32 + batch_num as u32);
        let input = build_tally_batch(
            state_tree_depth,
            1,
            vote_option_tree_depth,
            final_signups as u32,
            batch_num as u32,
            &state_tree,
            &users,
            &final_state_salt,
            &current_results,
            &current_results_root_salt,
            &new_results_root_salt,
        )?;
        current_results = tally_encoded_results(&current_results, &input.votes);
        current_results_root_salt = new_results_root_salt;
        stages.push(RoundStageInput {
            name: format!("{}-tally-{batch_num}", config.stage_prefix),
            stage: "tally".to_string(),
            input: ProverInput::TallyVotes(input),
        });
    }

    let mut votes = Vec::with_capacity(message_commands.len());
    for command in &message_commands {
        votes.push(RoundVote {
            state_index: command.state_index as u32,
            vote_option_index: command.vote_option_index as u32,
            new_vote_weight: command.new_vote_weight,
            expected_valid: command.valid,
            note: if command.valid {
                "valid vote".to_string()
            } else {
                "old key after deactivate".to_string()
            },
        });
    }

    let expected_raw_results = raw_vote_results(&users);
    Ok(SignupRoundFixture {
        round_id: config.round_id.to_string(),
        state_tree_depth,
        vote_option_tree_depth,
        process_message_batch_size: batch_size,
        tally_batch_size: batch_size,
        initial_signups,
        final_signups,
        message_count: message_commands.len(),
        deactivate_state_indices: deactivate_state_indices
            .into_iter()
            .map(|idx| idx as u32)
            .collect(),
        add_new_key_old_state_index: deactivate_state_indices[1] as u32,
        add_new_key_new_state_index: initial_signups as u32,
        votes,
        expected_raw_results,
        stages,
    })
}

pub fn five_signup_stage_input(name: &str) -> ProofResult<Option<ProverInput>> {
    let fixture = five_signup_round_fixture()?;
    Ok(fixture
        .stages
        .into_iter()
        .find(|stage| stage.name == name)
        .map(|stage| stage.input))
}

pub fn round_stage_input(name: &str) -> ProofResult<Option<ProverInput>> {
    if name.starts_with("fifty-signup-") {
        let fixture = fifty_signup_round_fixture()?;
        return Ok(fixture
            .stages
            .into_iter()
            .find(|stage| stage.name == name)
            .map(|stage| stage.input));
    }
    if name.starts_with("fifteen-signup-") {
        let fixture = fifteen_signup_round_fixture()?;
        return Ok(fixture
            .stages
            .into_iter()
            .find(|stage| stage.name == name)
            .map(|stage| stage.input));
    }
    five_signup_stage_input(name)
}

fn build_process_deactivate(
    coord_priv_key: &Field,
    coord_pub_key: &PubKey,
    poll_id: &Field,
    state_tree: &QuinTree,
    active_tree: &mut QuinTree,
    deactivate_tree: &mut QuinTree,
    users: &[User],
    deactivate_state_indices: [usize; 2],
    deactivate_index0: usize,
) -> ProofResult<ProcessDeactivateInput> {
    let batch_size = 5;
    let state_tree_depth = state_tree.depth;
    let zero = Field::from(0u32);
    let mut msgs = vec![[zero; 10]; batch_size];
    let mut enc_pub_keys = vec![[zero, zero]; batch_size];
    let mut kem_ciphertexts = vec![KemCiphertext::zero(); batch_size];
    let mut auth_pub_keys = vec![Vec::new(); batch_size];
    let mut auth_signatures = vec![Vec::new(); batch_size];
    let mut deactivate_kem_pub_keys = vec![KemPublicKey::zero(); batch_size];
    let mut deactivate_kem_randomness = vec![zero; batch_size];
    let mut deactivate_kem_ciphertexts = vec![KemCiphertext::zero(); batch_size];
    let mut c1 = vec![[zero, zero]; batch_size];
    let mut c2 = vec![[zero, zero]; batch_size];
    let mut current_state_leaves = vec![[zero; 10]; batch_size];
    let mut current_state_paths = vec![Vec::new(); batch_size];
    let mut active_paths = vec![Vec::new(); batch_size];
    let mut deactivate_paths = vec![Vec::new(); batch_size];
    let current_active_state = vec![zero; batch_size];
    let mut new_active_state = vec![Field::from(1u32); batch_size];

    for (slot, state_index) in deactivate_state_indices.into_iter().enumerate() {
        let user = &users[state_index];
        let command = command_fields(poll_id, state_index, 0, 0, 1, &user.pub_key);
        auth_pub_keys[slot] = user.auth_pub_key.clone();
        auth_signatures[slot] = sign_command_for_testing(&user.priv_key, &command);
        let encrypted =
            encrypt_command(coord_priv_key, &Field::from(8001u32 + slot as u32), command)?;
        msgs[slot] = encrypted.0;
        enc_pub_keys[slot] = encrypted.1;
        kem_ciphertexts[slot] = encrypted.2;
        current_state_leaves[slot] = user.state_leaf()?;
        current_state_paths[slot] = state_tree.path(state_index)?;
        active_paths[slot] = active_tree.path(state_index)?;
        deactivate_paths[slot] = deactivate_tree.path(deactivate_index0 + slot)?;
        let active_leaf = hash_fields(&[Field::from(state_index), poll_id.clone()]);
        new_active_state[slot] = active_leaf.clone();
        active_tree.set(state_index, active_leaf)?;

        let deactivate_randomness = Field::from(9001u32 + slot as u32);
        let (deactivate_ciphertext, _, shared_key) =
            crate::pq_kem::encapsulate_to_public_key_for_testing(
                &user.kem_pub_key,
                &deactivate_randomness,
            )?;
        let (c1_fields, c2_fields) =
            crate::pq_kem::deactivate_ciphertext_fields(&deactivate_ciphertext);
        c1[slot] = c1_fields;
        c2[slot] = c2_fields;
        deactivate_kem_pub_keys[slot] = user.kem_pub_key.clone();
        deactivate_kem_randomness[slot] = deactivate_randomness;
        deactivate_kem_ciphertexts[slot] = deactivate_ciphertext;
        let shared_key_hash = crate::pq_kem::shared_key_hash_fields(&shared_key);
        let deactivate_leaf = hash_fields(&[
            c1[slot][0].clone(),
            c1[slot][1].clone(),
            c2[slot][0].clone(),
            c2[slot][1].clone(),
            shared_key_hash,
        ]);
        deactivate_tree.set(deactivate_index0 + slot, deactivate_leaf)?;
    }

    let dummy_index = 5usize.pow(state_tree_depth as u32) - 1;
    for slot in 2..batch_size {
        current_state_paths[slot] = state_tree.path(dummy_index)?;
        active_paths[slot] = active_tree.path(dummy_index)?;
        deactivate_paths[slot] = deactivate_tree.path(deactivate_index0 + slot)?;
    }

    let current_active_state_root = zero_root(state_tree_depth)?;
    let current_deactivate_root = zero_root(state_tree_depth + 2)?;
    let current_deactivate_commitment =
        hash_pair(&current_active_state_root, &current_deactivate_root);
    let batch_start_hash = zero.clone();
    let batch_end_hash =
        message_chain(&batch_start_hash, &msgs, &enc_pub_keys, EmptyRule::Message0)?;
    let coord_pub_key_hash = hash_fields(coord_pub_key);
    let current_state_root = state_tree.root()?;
    let new_deactivate_root = deactivate_tree.root()?;
    let new_deactivate_commitment = hash_pair(&active_tree.root()?, &new_deactivate_root);
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
        expected_poll_id: poll_id.clone(),
        current_active_state_root,
        current_deactivate_root,
        batch_start_hash,
        batch_end_hash,
        coord_priv_key: coord_priv_key.clone(),
        coord_pub_key: coord_pub_key.clone(),
        msgs,
        enc_pub_keys,
        kem_ciphertexts,
        auth_pub_keys,
        auth_signatures,
        deactivate_kem_pub_keys,
        deactivate_kem_randomness,
        deactivate_kem_ciphertexts,
        c1,
        c2,
        current_active_state,
        new_active_state,
        deactivate_index0: Field::from(deactivate_index0),
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

fn build_add_new_key(
    state_tree_depth: usize,
    coord_pub_key: &PubKey,
    poll_id: &Field,
    old_user: &User,
    replacement: &User,
    deactivate_tree: &QuinTree,
    deactivate_index: usize,
    deactivate_slot: usize,
) -> ProofResult<AddNewKeyInput> {
    let deactivate_randomness = Field::from(9001u32 + deactivate_slot as u32);
    let (deactivate_kem_ciphertext, _, shared_key) =
        crate::pq_kem::encapsulate_to_public_key_for_testing(
            &old_user.kem_pub_key,
            &deactivate_randomness,
        )?;
    let (c1, c2) = crate::pq_kem::deactivate_ciphertext_fields(&deactivate_kem_ciphertext);
    let shared_key_hash = crate::pq_kem::shared_key_hash_fields(&shared_key);
    let deactivate_leaf = hash_fields(&[
        c1[0].clone(),
        c1[1].clone(),
        c2[0].clone(),
        c2[1].clone(),
        shared_key_hash,
    ]);
    let nullifier = hash_pair(&old_user.priv_key, poll_id);
    let random_val = Field::from(42u32);
    let (d1, d2) = native_rerandomize_ciphertext(coord_pub_key, &c1, &c2, &random_val);
    let coord_pub_key_hash = hash_fields(coord_pub_key);
    let new_pub_key_hash = hash_fields(&replacement.pub_key);
    let deactivate_root = deactivate_tree.root()?;
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
        coord_pub_key: coord_pub_key.clone(),
        deactivate_root,
        deactivate_index: Field::from(deactivate_index),
        deactivate_leaf,
        c1,
        c2,
        deactivate_kem_ciphertext,
        random_val,
        d1,
        d2,
        deactivate_leaf_path_elements: deactivate_tree.path(deactivate_index)?,
        nullifier,
        old_private_key: old_user.priv_key.clone(),
        new_pub_key: replacement.pub_key.clone(),
        poll_id: poll_id.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_process_messages_batch(
    coord_priv_key: &Field,
    coord_pub_key: &PubKey,
    poll_id: &Field,
    batch_size: usize,
    num_signups: u32,
    batch_start_hash: Field,
    current_state_salt: Field,
    new_state_salt: Field,
    active_tree: &QuinTree,
    deactivate_tree: &QuinTree,
    state_tree: &mut QuinTree,
    users: &mut [User],
    commands: &[VoteCommand],
) -> ProofResult<ProcessMessagesInput> {
    let zero = Field::from(0u32);
    let state_tree_depth = state_tree.depth;
    let vote_option_tree_depth = 1;
    let dummy_index = 5usize.pow(state_tree_depth as u32) - 1;
    let mut msgs = vec![[zero; 10]; batch_size];
    let mut enc_pub_keys = vec![[zero, zero]; batch_size];
    let mut kem_ciphertexts = vec![KemCiphertext::zero(); batch_size];
    let mut auth_pub_keys = vec![Vec::new(); batch_size];
    let mut auth_signatures = vec![Vec::new(); batch_size];
    let mut current_state_leaves = vec![[zero; 10]; batch_size];
    let mut current_state_paths = vec![Vec::new(); batch_size];
    let mut active_state_leaves = vec![zero; batch_size];
    let mut active_paths = vec![Vec::new(); batch_size];
    let mut current_vote_weights = vec![zero; batch_size];
    let mut current_vote_paths = vec![Vec::new(); batch_size];

    let current_state_root = state_tree.root()?;
    let current_state_commitment = hash_pair(&current_state_root, &current_state_salt);
    let active_state_root = active_tree.root()?;
    let deactivate_root = deactivate_tree.root()?;
    let deactivate_commitment = hash_pair(&active_state_root, &deactivate_root);

    for (command_offset, command) in commands.iter().enumerate() {
        let slot = batch_size - 1 - command_offset;
        let user = &users[command.state_index];
        let nonce = user.nonce.to_u32().unwrap_or(0) + 1;
        let command_fields = command_fields(
            poll_id,
            command.state_index,
            command.vote_option_index,
            command.new_vote_weight,
            nonce,
            &command.new_pub_key,
        );
        auth_pub_keys[slot] = user.auth_pub_key.clone();
        auth_signatures[slot] = sign_command_for_testing(&command.user_priv_key, &command_fields);
        let encrypted = encrypt_command(
            coord_priv_key,
            &Field::from(10_001u32 + slot as u32),
            command_fields,
        )?;
        msgs[slot] = encrypted.0;
        enc_pub_keys[slot] = encrypted.1;
        kem_ciphertexts[slot] = encrypted.2;
        current_state_leaves[slot] = user.state_leaf()?;
        current_state_paths[slot] = state_tree.path(command.state_index)?;
        active_state_leaves[slot] = active_tree.leaf(command.state_index).clone();
        active_paths[slot] = active_tree.path(command.state_index)?;
        current_vote_weights[slot] = user.votes[command.vote_option_index].clone();
        current_vote_paths[slot] = vote_path(&user.votes, command.vote_option_index);

        if command.valid {
            users[command.state_index].votes[command.vote_option_index] =
                Field::from(command.new_vote_weight);
            users[command.state_index].nonce = Field::from(nonce);
            users[command.state_index].balance -= Field::from(command.new_vote_weight);
            users[command.state_index].pub_key = command.new_pub_key.clone();
            state_tree.set(
                command.state_index,
                hash_state_leaf(&users[command.state_index].state_leaf()?)?,
            )?;
        }
    }

    for slot in 0..batch_size.saturating_sub(commands.len()) {
        current_state_paths[slot] = state_tree.path(dummy_index)?;
        active_paths[slot] = active_tree.path(dummy_index)?;
        current_vote_paths[slot] = vote_path(&[zero; VOTE_ROW_WORDS], 0);
    }

    let batch_end_hash = message_chain(
        &batch_start_hash,
        &msgs,
        &enc_pub_keys,
        EmptyRule::EncPubKeyX,
    )?;
    let new_state_root = state_tree.root()?;
    let new_state_commitment = hash_pair(&new_state_root, &new_state_salt);
    let packed_vals = Field::from(5u32) + (Field::from(num_signups) << 32usize);
    let coord_pub_key_hash = hash_fields(coord_pub_key);
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
        expected_poll_id: poll_id.clone(),
        batch_start_hash,
        batch_end_hash,
        coord_priv_key: coord_priv_key.clone(),
        coord_pub_key: coord_pub_key.clone(),
        msgs,
        enc_pub_keys,
        kem_ciphertexts,
        auth_pub_keys,
        auth_signatures,
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
        active_state_leaves,
        active_state_leaves_path_elements: active_paths,
        current_vote_weights,
        current_vote_weights_path_elements: current_vote_paths,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_tally_batch(
    state_tree_depth: usize,
    int_state_tree_depth: usize,
    vote_option_tree_depth: usize,
    num_signups: u32,
    batch_num: u32,
    state_tree: &QuinTree,
    users: &[User],
    state_salt: &Field,
    current_results: &[Field],
    current_results_root_salt: &Field,
    new_results_root_salt: &Field,
) -> ProofResult<TallyVotesInput> {
    let batch_size = 5usize.pow(int_state_tree_depth as u32);
    let start = batch_num as usize * batch_size;
    let zero_state_leaf = [Field::from(0u32); 10];
    let mut state_leaf = Vec::with_capacity(batch_size);
    let mut votes = Vec::with_capacity(batch_size);
    for idx in start..start + batch_size {
        if idx < users.len() {
            state_leaf.push(users[idx].state_leaf()?);
            votes.push(users[idx].votes);
        } else {
            state_leaf.push(zero_state_leaf.clone());
            votes.push([Field::from(0u32); VOTE_ROW_WORDS]);
        }
    }
    let state_root = state_tree.root()?;
    let state_commitment = hash_pair(&state_root, state_salt);
    let current_results = if current_results.is_empty() {
        vec![Field::from(0u32); VOTE_ROW_WORDS]
    } else {
        current_results.to_vec()
    };
    let current_results_root = vote_root(slice_to_vote_row(&current_results)?)?;
    let current_tally_commitment = if batch_num == 0 {
        Field::from(0u32)
    } else {
        hash_pair(&current_results_root, current_results_root_salt)
    };
    let new_results = tally_encoded_results(&current_results, &votes);
    let new_results_root = vote_root(slice_to_vote_row(&new_results)?)?;
    let new_tally_commitment = hash_pair(&new_results_root, new_results_root_salt);
    let packed_vals = (Field::from(num_signups) << 32usize) + Field::from(batch_num);
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
        state_salt: *state_salt,
        state_commitment,
        current_tally_commitment,
        new_tally_commitment,
        state_leaf,
        state_path_elements: state_tree.subtree_path(batch_num as usize, int_state_tree_depth)?,
        votes,
        current_results,
        current_results_root_salt: current_results_root_salt.clone(),
        new_results_root_salt: new_results_root_salt.clone(),
    })
}

fn tally_encoded_results(current_results: &[Field], rows: &[VoteRow]) -> Vec<Field> {
    let max_votes = Field::from(10u32).pow(Field::from(24u32));
    let mut out = current_results.to_vec();
    for row in rows {
        for (idx, vote) in row.iter().enumerate() {
            out[idx] += vote * (vote + &max_votes);
        }
    }
    out
}

fn raw_vote_results(users: &[User]) -> [u128; VOTE_ROW_WORDS] {
    let mut results = [0u128; VOTE_ROW_WORDS];
    for user in users {
        for (idx, vote) in user.votes.iter().enumerate() {
            results[idx] += vote
                .to_u128()
                .expect("fixture vote weight must fit in u128");
        }
    }
    results
}

fn slice_to_vote_row(values: &[Field]) -> ProofResult<&VoteRow> {
    values
        .try_into()
        .map_err(|_| crate::ProofError::InvalidLength {
            name: "vote row slice",
            expected: VOTE_ROW_WORDS,
            actual: values.len(),
        })
}

fn vote_root(votes: &VoteRow) -> ProofResult<Field> {
    hash5_exact(votes)
}

fn vote_path(votes: &VoteRow, index: usize) -> PathElements {
    let mut siblings = [Field::from(0u32); 4];
    let mut out = 0;
    for (idx, vote) in votes.iter().enumerate() {
        if idx != index {
            siblings[out] = vote.clone();
            out += 1;
        }
    }
    vec![siblings]
}

fn command_fields(
    poll_id: &Field,
    state_index: usize,
    vote_option_index: usize,
    new_vote_weight: u32,
    nonce: u32,
    new_pub_key: &PubKey,
) -> [Field; 3] {
    [
        pack_command_data(
            poll_id,
            &Field::from(0u32),
            &Field::from(0u32),
            &Field::from(new_vote_weight),
            &Field::from(vote_option_index),
            &Field::from(state_index),
            &Field::from(nonce),
        ),
        new_pub_key[0].clone(),
        new_pub_key[1].clone(),
    ]
}

fn encrypt_command(
    coord_priv_key: &Field,
    randomness: &Field,
    command: [Field; 3],
) -> ProofResult<(Message, PubKey, KemCiphertext)> {
    let zero = Field::from(0u32);
    let (kem_ciphertext, compact, shared_key) =
        crate::pq_kem::encapsulate_to_seed_for_testing(coord_priv_key, randomness)?;
    let mut plaintext = vec![
        command[0].clone(),
        command[1].clone(),
        command[2].clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
    ];
    plaintext.resize(9, zero.clone());
    let ciphertext = native_encrypt_for_testing(&plaintext, &shared_key, &zero, 7)?;
    let message = ciphertext.try_into().map_err(|ciphertext: Vec<Field>| {
        crate::ProofError::InvalidLength {
            name: "native message ciphertext",
            expected: 10,
            actual: ciphertext.len(),
        }
    })?;
    Ok((message, compact, kem_ciphertext))
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

#[derive(Clone)]
struct QuinTree {
    leaves: Vec<Field>,
    depth: usize,
}

impl QuinTree {
    fn zeros(size: usize, depth: usize) -> ProofResult<Self> {
        Self::new(vec![Field::from(0u32); size], depth)
    }

    fn new(leaves: Vec<Field>, depth: usize) -> ProofResult<Self> {
        let expected = 5usize.pow(depth as u32);
        if leaves.len() != expected {
            return Err(crate::ProofError::InvalidLength {
                name: "fixture quin leaves",
                expected,
                actual: leaves.len(),
            });
        }
        Ok(Self { leaves, depth })
    }

    fn leaf(&self, index: usize) -> &Field {
        &self.leaves[index]
    }

    fn set(&mut self, index: usize, leaf: Field) -> ProofResult<()> {
        if index >= self.leaves.len() {
            return Err(crate::ProofError::InvalidLength {
                name: "fixture quin index",
                expected: self.leaves.len(),
                actual: index + 1,
            });
        }
        self.leaves[index] = leaf;
        Ok(())
    }

    fn root(&self) -> ProofResult<Field> {
        self.root_and_path(0).map(|(root, _)| root)
    }

    fn path(&self, index: usize) -> ProofResult<Vec<PathElement>> {
        self.root_and_path(index).map(|(_, path)| path)
    }

    fn subtree_path(
        &self,
        subtree_index: usize,
        subtree_depth: usize,
    ) -> ProofResult<Vec<PathElement>> {
        let subtree_size = 5usize.pow(subtree_depth as u32);
        let upper_depth = self.depth.checked_sub(subtree_depth).ok_or_else(|| {
            crate::ProofError::Crypto("fixture subtree depth exceeds tree depth".to_string())
        })?;
        let mut level = self.leaves.clone();
        for _ in 0..subtree_depth {
            let mut next = Vec::with_capacity(level.len() / 5);
            for chunk in level.chunks(5) {
                next.push(hash5_exact(chunk)?);
            }
            level = next;
        }
        let upper_tree = QuinTree::new(level, upper_depth)?;
        let _ = subtree_size;
        upper_tree.path(subtree_index)
    }

    fn root_and_path(&self, index: usize) -> ProofResult<(Field, Vec<PathElement>)> {
        let mut level = self.leaves.clone();
        let mut idx = index;
        let mut path = Vec::with_capacity(self.depth);
        for _ in 0..self.depth {
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
}
