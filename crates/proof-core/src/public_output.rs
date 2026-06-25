use crate::field::Field;
use crate::native_types::{field_to_digest, Commitment, Digest, InputHash, Root};
use serde::{Deserialize, Serialize};

pub type PublicValue = Digest;

pub fn public_value(value: &Field) -> PublicValue {
    field_to_digest(value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicOutput {
    ProcessMessages(ProcessMessagesPublicOutput),
    TallyVotes(TallyVotesPublicOutput),
    ProcessDeactivate(ProcessDeactivatePublicOutput),
    AddNewKey(AddNewKeyPublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMessagesPublicOutput {
    pub input_hash: InputHash,
    pub packed_vals: PublicValue,
    pub coord_pub_key_hash: PublicValue,
    pub batch_start_hash: Digest,
    pub batch_end_hash: Digest,
    pub current_state_commitment: Commitment,
    pub new_state_commitment: Commitment,
    pub deactivate_commitment: Commitment,
    pub expected_poll_id: PublicValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyVotesPublicOutput {
    pub input_hash: InputHash,
    pub packed_vals: PublicValue,
    pub state_commitment: Commitment,
    pub current_tally_commitment: Commitment,
    pub new_tally_commitment: Commitment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessDeactivatePublicOutput {
    pub input_hash: InputHash,
    pub new_deactivate_root: Root,
    pub coord_pub_key_hash: PublicValue,
    pub batch_start_hash: Digest,
    pub batch_end_hash: Digest,
    pub current_deactivate_commitment: Commitment,
    pub new_deactivate_commitment: Commitment,
    pub current_state_root: Root,
    pub expected_poll_id: PublicValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddNewKeyPublicOutput {
    pub input_hash: InputHash,
    pub deactivate_root: Root,
    pub coord_pub_key_hash: PublicValue,
    pub nullifier: PublicValue,
    pub d1: [PublicValue; 2],
    pub d2: [PublicValue; 2],
    pub new_pub_key_hash: PublicValue,
    pub poll_id: PublicValue,
}
