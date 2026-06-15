use crate::field::Field;
use serde::{Deserialize, Serialize};

pub type PubKey = [Field; 2];
pub type Message = Vec<Field>;
pub type PathElements = Vec<Vec<Field>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProverInput {
    ProcessMessages(ProcessMessagesInput),
    TallyVotes(TallyVotesInput),
    ProcessDeactivate(ProcessDeactivateInput),
    AddNewKey(AddNewKeyInput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMessagesInput {
    pub state_tree_depth: usize,
    pub vote_option_tree_depth: usize,
    pub batch_size: usize,
    pub input_hash: Field,
    pub packed_vals: Field,
    pub expected_poll_id: Field,
    pub batch_start_hash: Field,
    pub batch_end_hash: Field,
    pub coord_priv_key: Field,
    pub coord_pub_key: PubKey,
    pub msgs: Vec<Message>,
    pub enc_pub_keys: Vec<PubKey>,
    pub current_state_root: Field,
    pub current_state_leaves: Vec<Vec<Field>>,
    pub current_state_leaves_path_elements: Vec<PathElements>,
    pub current_state_commitment: Field,
    pub current_state_salt: Field,
    pub new_state_commitment: Field,
    pub new_state_salt: Field,
    pub active_state_root: Field,
    pub deactivate_root: Field,
    pub deactivate_commitment: Field,
    pub active_state_leaves: Vec<Field>,
    pub active_state_leaves_path_elements: Vec<PathElements>,
    pub current_vote_weights: Vec<Field>,
    pub current_vote_weights_path_elements: Vec<PathElements>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyVotesInput {
    pub state_tree_depth: usize,
    pub int_state_tree_depth: usize,
    pub vote_option_tree_depth: usize,
    pub input_hash: Field,
    pub packed_vals: Field,
    pub state_root: Field,
    pub state_salt: Field,
    pub state_commitment: Field,
    pub current_tally_commitment: Field,
    pub new_tally_commitment: Field,
    pub state_leaf: Vec<Vec<Field>>,
    pub state_path_elements: PathElements,
    pub votes: Vec<Vec<Field>>,
    pub current_results: Vec<Field>,
    pub current_results_root_salt: Field,
    pub new_results_root_salt: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessDeactivateInput {
    pub state_tree_depth: usize,
    pub batch_size: usize,
    pub input_hash: Field,
    pub expected_poll_id: Field,
    pub current_active_state_root: Field,
    pub current_deactivate_root: Field,
    pub batch_start_hash: Field,
    pub batch_end_hash: Field,
    pub coord_priv_key: Field,
    pub coord_pub_key: PubKey,
    pub msgs: Vec<Message>,
    pub enc_pub_keys: Vec<PubKey>,
    pub c1: Vec<PubKey>,
    pub c2: Vec<PubKey>,
    pub current_active_state: Vec<Field>,
    pub new_active_state: Vec<Field>,
    pub deactivate_index0: Field,
    pub current_state_root: Field,
    pub current_state_leaves: Vec<Vec<Field>>,
    pub current_state_leaves_path_elements: Vec<PathElements>,
    pub active_state_leaves_path_elements: Vec<PathElements>,
    pub deactivate_leaves_path_elements: Vec<PathElements>,
    pub current_deactivate_commitment: Field,
    pub new_deactivate_root: Field,
    pub new_deactivate_commitment: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddNewKeyInput {
    pub state_tree_depth: usize,
    pub input_hash: Field,
    pub coord_pub_key: PubKey,
    pub deactivate_root: Field,
    pub deactivate_index: Field,
    pub deactivate_leaf: Field,
    pub c1: PubKey,
    pub c2: PubKey,
    pub random_val: Field,
    pub d1: PubKey,
    pub d2: PubKey,
    pub deactivate_leaf_path_elements: PathElements,
    pub nullifier: Field,
    pub old_private_key: Field,
    pub new_pub_key: PubKey,
    pub poll_id: Field,
}
