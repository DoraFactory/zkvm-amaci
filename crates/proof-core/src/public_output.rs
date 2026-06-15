use crate::field::Field;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicOutput {
    ProcessMessages(ProcessMessagesPublicOutput),
    TallyVotes(TallyVotesPublicOutput),
    ProcessDeactivate(ProcessDeactivatePublicOutput),
    AddNewKey(AddNewKeyPublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMessagesPublicOutput {
    pub input_hash: Field,
    pub packed_vals: Field,
    pub coord_pub_key_hash: Field,
    pub batch_start_hash: Field,
    pub batch_end_hash: Field,
    pub current_state_commitment: Field,
    pub new_state_commitment: Field,
    pub deactivate_commitment: Field,
    pub expected_poll_id: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyVotesPublicOutput {
    pub input_hash: Field,
    pub packed_vals: Field,
    pub state_commitment: Field,
    pub current_tally_commitment: Field,
    pub new_tally_commitment: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessDeactivatePublicOutput {
    pub input_hash: Field,
    pub new_deactivate_root: Field,
    pub coord_pub_key_hash: Field,
    pub batch_start_hash: Field,
    pub batch_end_hash: Field,
    pub current_deactivate_commitment: Field,
    pub new_deactivate_commitment: Field,
    pub current_state_root: Field,
    pub expected_poll_id: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddNewKeyPublicOutput {
    pub input_hash: Field,
    pub deactivate_root: Field,
    pub coord_pub_key_hash: Field,
    pub nullifier: Field,
    pub d1: [Field; 2],
    pub d2: [Field; 2],
    pub new_pub_key_hash: Field,
    pub poll_id: Field,
}
