use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::packing::{decode_vote_weight_96, unpack_element_high_to_low};
use num_traits::ToPrimitive;
use sha2::{Digest as Sha2Digest, Sha256};

pub type Digest = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCommand {
    pub poll_id: u32,
    pub nonce: u32,
    pub state_index: u32,
    pub vote_option_index: u32,
    pub new_vote_weight: u128,
    pub new_pub_key: [Digest; 2],
}

impl NativeCommand {
    pub fn from_packed_fields(packed_command: &[Field; 3]) -> ProofResult<Self> {
        let chunks = unpack_element_high_to_low(&packed_command[0], 7)?;
        let new_vote_weight = decode_vote_weight_96(&chunks[1], &chunks[2], &chunks[3])?;
        Ok(Self {
            poll_id: to_u32("native command poll_id", &chunks[0])?,
            nonce: to_u32("native command nonce", &chunks[6])?,
            state_index: to_u32("native command state_index", &chunks[5])?,
            vote_option_index: to_u32("native command vote_option_index", &chunks[4])?,
            new_vote_weight: to_u128("native command new_vote_weight", &new_vote_weight)?,
            new_pub_key: [
                field_to_digest(&packed_command[1]),
                field_to_digest(&packed_command[2]),
            ],
        })
    }

    pub fn message_digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"AMACI_ZKVM_NATIVE_COMMAND_V2");
        hasher.update(self.poll_id.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.state_index.to_be_bytes());
        hasher.update(self.vote_option_index.to_be_bytes());
        hasher.update(self.new_vote_weight.to_be_bytes());
        hasher.update(self.new_pub_key[0]);
        hasher.update(self.new_pub_key[1]);
        hasher.finalize().into()
    }
}

pub fn digest_to_field(digest: Digest) -> Field {
    Field::from_be_bytes(digest)
}

pub fn field_to_digest(value: &Field) -> Digest {
    value.to_be_bytes()
}

fn to_u32(name: &'static str, value: &Field) -> ProofResult<u32> {
    value.to_u32().ok_or_else(|| ProofError::InvalidRange {
        name,
        value: value.clone(),
        max: Field::from(u32::MAX),
    })
}

fn to_u128(name: &'static str, value: &Field) -> ProofResult<u128> {
    value.to_u128().ok_or_else(|| ProofError::InvalidRange {
        name,
        value: value.clone(),
        max: Field::from(u128::MAX),
    })
}
