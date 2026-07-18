use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::packing::{decode_vote_weight_96, unpack_element_high_to_low_array};
use num_traits::ToPrimitive;
use sha2::{Digest as Sha2Digest, Sha256};

pub type Digest = [u8; 32];
pub type Commitment = Digest;
pub type InputHash = Digest;
pub type Root = Digest;

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
        let chunks = unpack_element_high_to_low_array::<7>(&packed_command[0])?;
        let new_vote_weight = decode_vote_weight_96(&chunks[1], &chunks[2], &chunks[3])?;
        Self::from_fields(
            &chunks[0],
            &chunks[6],
            &chunks[5],
            &chunks[4],
            &new_vote_weight,
            &[packed_command[1], packed_command[2]],
        )
    }

    pub(crate) fn from_fields(
        poll_id: &Field,
        nonce: &Field,
        state_index: &Field,
        vote_option_index: &Field,
        new_vote_weight: &Field,
        new_pub_key: &[Field; 2],
    ) -> ProofResult<Self> {
        Ok(Self {
            poll_id: to_u32("native command poll_id", poll_id)?,
            nonce: to_u32("native command nonce", nonce)?,
            state_index: to_u32("native command state_index", state_index)?,
            vote_option_index: to_u32("native command vote_option_index", vote_option_index)?,
            new_vote_weight: to_u128("native command new_vote_weight", new_vote_weight)?,
            new_pub_key: [
                field_to_digest(&new_pub_key[0]),
                field_to_digest(&new_pub_key[1]),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_command_matches_packed_command_digest() {
        let poll_id = Field::from(7u32);
        let nonce = Field::from(9u32);
        let state_index = Field::from(11u32);
        let vote_option_index = Field::from(3u32);
        let new_vote_weight = Field::from(123_456_789u128);
        let new_pub_key = [Field::from(101u32), Field::from(202u32)];
        let packed = poll_id << 192usize
            | new_vote_weight << 96usize
            | vote_option_index << 64usize
            | state_index << 32usize
            | nonce;
        let packed_command = [packed, new_pub_key[0], new_pub_key[1]];

        let from_packed = NativeCommand::from_packed_fields(&packed_command).unwrap();
        let from_fields = NativeCommand::from_fields(
            &poll_id,
            &nonce,
            &state_index,
            &vote_option_index,
            &new_vote_weight,
            &new_pub_key,
        )
        .unwrap();

        assert_eq!(from_fields, from_packed);
        assert_eq!(from_fields.message_digest(), from_packed.message_digest());
    }
}
