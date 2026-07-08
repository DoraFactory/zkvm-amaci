use crate::codec::decode_public_output;
use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::native_types::Digest;
use crate::packing::{unpack_process_messages_packed_vals, unpack_tally_packed_vals};
use crate::public_output::PublicOutput;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

const AGGREGATE_MAGIC: &[u8; 8] = b"AMACIAG1";
const TAG_PROCESS_MESSAGES: u8 = 1;
const TAG_TALLY: u8 = 2;
const CHILD_OUTPUTS_HASH_DOMAIN: &[u8] = b"AMACI_ZKVM_AGG_CHILD_PUBLIC_OUTPUTS_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregatePublicOutput {
    ProcessMessages(ProcessMessagesAggregatePublicOutput),
    Tally(TallyAggregatePublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMessagesAggregatePublicOutput {
    pub child_count: u32,
    pub packed_vals: Digest,
    pub coord_pub_key_hash: Digest,
    pub initial_batch_start_hash: Digest,
    pub final_batch_end_hash: Digest,
    pub initial_state_commitment: Digest,
    pub final_state_commitment: Digest,
    pub deactivate_commitment: Digest,
    pub expected_poll_id: Digest,
    pub child_public_outputs_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyAggregatePublicOutput {
    pub child_count: u32,
    pub first_batch_num: u32,
    pub last_batch_num: u32,
    pub state_commitment: Digest,
    pub initial_tally_commitment: Digest,
    pub final_tally_commitment: Digest,
    pub child_public_outputs_hash: Digest,
}

pub fn build_process_messages_aggregate_public_output(
    child_public_outputs: &[Vec<u8>],
) -> ProofResult<ProcessMessagesAggregatePublicOutput> {
    if child_public_outputs.is_empty() {
        return Err(ProofError::InvalidLength {
            name: "process messages aggregate child proofs",
            expected: 1,
            actual: 0,
        });
    }

    let mut packed_vals = None;
    let mut coord_pub_key_hash = None;
    let mut initial_batch_start_hash = None;
    let mut previous_batch_end_hash = None;
    let mut initial_state_commitment = None;
    let mut previous_new_state_commitment = None;
    let mut deactivate_commitment = None;
    let mut expected_poll_id = None;

    for (idx, public_bytes) in child_public_outputs.iter().enumerate() {
        let output = match decode_public_output(public_bytes)? {
            PublicOutput::ProcessMessages(output) => output,
            _ => {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} is not a process messages public output"
                )));
            }
        };
        unpack_process_messages_packed_vals(&Field::from_be_bytes(output.packed_vals))?;

        if idx == 0 {
            packed_vals = Some(output.packed_vals);
            coord_pub_key_hash = Some(output.coord_pub_key_hash);
            initial_batch_start_hash = Some(output.batch_start_hash);
            initial_state_commitment = Some(output.current_state_commitment);
            deactivate_commitment = Some(output.deactivate_commitment);
            expected_poll_id = Some(output.expected_poll_id);
        } else {
            if Some(output.packed_vals) != packed_vals {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} packed values mismatch"
                )));
            }
            if Some(output.coord_pub_key_hash) != coord_pub_key_hash {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} coordinator key hash mismatch"
                )));
            }
            if Some(output.deactivate_commitment) != deactivate_commitment {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} deactivate commitment mismatch"
                )));
            }
            if Some(output.expected_poll_id) != expected_poll_id {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} poll id mismatch"
                )));
            }
            if Some(output.batch_start_hash) != previous_batch_end_hash {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} batch hash chain mismatch"
                )));
            }
            if Some(output.current_state_commitment) != previous_new_state_commitment {
                return Err(ProofError::Codec(format!(
                    "process messages aggregate child {idx} state commitment chain mismatch"
                )));
            }
        }

        previous_batch_end_hash = Some(output.batch_end_hash);
        previous_new_state_commitment = Some(output.new_state_commitment);
    }

    Ok(ProcessMessagesAggregatePublicOutput {
        child_count: child_public_outputs.len().try_into().map_err(|_| {
            ProofError::Codec("too many process messages aggregate children".to_string())
        })?,
        packed_vals: packed_vals.expect("non-empty child output list has packed vals"),
        coord_pub_key_hash: coord_pub_key_hash
            .expect("non-empty child output list has coordinator key hash"),
        initial_batch_start_hash: initial_batch_start_hash
            .expect("non-empty child output list has initial batch hash"),
        final_batch_end_hash: previous_batch_end_hash
            .expect("non-empty child output list has final batch hash"),
        initial_state_commitment: initial_state_commitment
            .expect("non-empty child output list has initial state"),
        final_state_commitment: previous_new_state_commitment
            .expect("non-empty child output list has final state"),
        deactivate_commitment: deactivate_commitment
            .expect("non-empty child output list has deactivate commitment"),
        expected_poll_id: expected_poll_id.expect("non-empty child output list has poll id"),
        child_public_outputs_hash: child_public_outputs_hash(child_public_outputs),
    })
}

pub fn build_tally_aggregate_public_output(
    child_public_outputs: &[Vec<u8>],
) -> ProofResult<TallyAggregatePublicOutput> {
    if child_public_outputs.is_empty() {
        return Err(ProofError::InvalidLength {
            name: "tally aggregate child proofs",
            expected: 1,
            actual: 0,
        });
    }

    let mut first_batch_num = None;
    let mut last_batch_num = 0u32;
    let mut state_commitment = None;
    let mut initial_tally_commitment = None;
    let mut previous_new_tally = None;

    for (idx, public_bytes) in child_public_outputs.iter().enumerate() {
        let output = match decode_public_output(public_bytes)? {
            PublicOutput::TallyVotes(output) => output,
            _ => {
                return Err(ProofError::Codec(format!(
                    "tally aggregate child {idx} is not a tally public output"
                )));
            }
        };
        let packed = unpack_tally_packed_vals(&Field::from_be_bytes(output.packed_vals))?;
        let batch_num = packed
            .batch_num
            .to_u32()
            .ok_or_else(|| ProofError::Codec("tally batch_num does not fit u32".to_string()))?;

        if idx == 0 {
            first_batch_num = Some(batch_num);
            state_commitment = Some(output.state_commitment);
            initial_tally_commitment = Some(output.current_tally_commitment);
        } else {
            let expected_batch = last_batch_num.checked_add(1).ok_or_else(|| {
                ProofError::Codec("tally aggregate batch_num overflow".to_string())
            })?;
            if batch_num != expected_batch {
                return Err(ProofError::Codec(format!(
                    "tally aggregate child {idx} batch_num {batch_num} did not follow {last_batch_num}"
                )));
            }
            if Some(output.state_commitment) != state_commitment {
                return Err(ProofError::Codec(format!(
                    "tally aggregate child {idx} state commitment mismatch"
                )));
            }
            if Some(output.current_tally_commitment) != previous_new_tally {
                return Err(ProofError::Codec(format!(
                    "tally aggregate child {idx} current tally commitment mismatch"
                )));
            }
        }

        last_batch_num = batch_num;
        previous_new_tally = Some(output.new_tally_commitment);
    }

    Ok(TallyAggregatePublicOutput {
        child_count: child_public_outputs
            .len()
            .try_into()
            .map_err(|_| ProofError::Codec("too many tally aggregate children".to_string()))?,
        first_batch_num: first_batch_num.expect("non-empty child output list has a first batch"),
        last_batch_num,
        state_commitment: state_commitment.expect("non-empty child output list has state"),
        initial_tally_commitment: initial_tally_commitment
            .expect("non-empty child output list has initial tally"),
        final_tally_commitment: previous_new_tally
            .expect("non-empty child output list has final tally"),
        child_public_outputs_hash: child_public_outputs_hash(child_public_outputs),
    })
}

pub fn child_public_outputs_hash(child_public_outputs: &[Vec<u8>]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(CHILD_OUTPUTS_HASH_DOMAIN);
    hasher.update((child_public_outputs.len() as u64).to_be_bytes());
    for public_bytes in child_public_outputs {
        hasher.update((public_bytes.len() as u64).to_be_bytes());
        hasher.update(public_bytes);
    }
    hasher.finalize().into()
}

pub fn encode_aggregate_public_output(output: &AggregatePublicOutput) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(AGGREGATE_MAGIC);
    match output {
        AggregatePublicOutput::ProcessMessages(output) => {
            out.push(TAG_PROCESS_MESSAGES);
            write_u32(&mut out, output.child_count);
            write_digest(&mut out, &output.packed_vals);
            write_digest(&mut out, &output.coord_pub_key_hash);
            write_digest(&mut out, &output.initial_batch_start_hash);
            write_digest(&mut out, &output.final_batch_end_hash);
            write_digest(&mut out, &output.initial_state_commitment);
            write_digest(&mut out, &output.final_state_commitment);
            write_digest(&mut out, &output.deactivate_commitment);
            write_digest(&mut out, &output.expected_poll_id);
            write_digest(&mut out, &output.child_public_outputs_hash);
        }
        AggregatePublicOutput::Tally(output) => {
            out.push(TAG_TALLY);
            write_u32(&mut out, output.child_count);
            write_u32(&mut out, output.first_batch_num);
            write_u32(&mut out, output.last_batch_num);
            write_digest(&mut out, &output.state_commitment);
            write_digest(&mut out, &output.initial_tally_commitment);
            write_digest(&mut out, &output.final_tally_commitment);
            write_digest(&mut out, &output.child_public_outputs_hash);
        }
    }
    out
}

pub fn decode_aggregate_public_output(bytes: &[u8]) -> ProofResult<AggregatePublicOutput> {
    let mut input = AggregateDecoder::new(bytes);
    input.expect_bytes("aggregate public codec magic", AGGREGATE_MAGIC)?;
    let tag = input.read_u8("aggregate public output tag")?;
    let decoded = match tag {
        TAG_PROCESS_MESSAGES => {
            AggregatePublicOutput::ProcessMessages(ProcessMessagesAggregatePublicOutput {
                child_count: input.read_u32("process messages aggregate child_count")?,
                packed_vals: input.read_digest("process messages aggregate packed_vals")?,
                coord_pub_key_hash: input
                    .read_digest("process messages aggregate coord_pub_key_hash")?,
                initial_batch_start_hash: input
                    .read_digest("process messages aggregate initial_batch_start_hash")?,
                final_batch_end_hash: input
                    .read_digest("process messages aggregate final_batch_end_hash")?,
                initial_state_commitment: input
                    .read_digest("process messages aggregate initial_state_commitment")?,
                final_state_commitment: input
                    .read_digest("process messages aggregate final_state_commitment")?,
                deactivate_commitment: input
                    .read_digest("process messages aggregate deactivate_commitment")?,
                expected_poll_id: input
                    .read_digest("process messages aggregate expected_poll_id")?,
                child_public_outputs_hash: input
                    .read_digest("process messages aggregate child_public_outputs_hash")?,
            })
        }
        TAG_TALLY => AggregatePublicOutput::Tally(TallyAggregatePublicOutput {
            child_count: input.read_u32("tally aggregate child_count")?,
            first_batch_num: input.read_u32("tally aggregate first_batch_num")?,
            last_batch_num: input.read_u32("tally aggregate last_batch_num")?,
            state_commitment: input.read_digest("tally aggregate state_commitment")?,
            initial_tally_commitment: input
                .read_digest("tally aggregate initial_tally_commitment")?,
            final_tally_commitment: input.read_digest("tally aggregate final_tally_commitment")?,
            child_public_outputs_hash: input
                .read_digest("tally aggregate child_public_outputs_hash")?,
        }),
        _ => {
            return Err(ProofError::Codec(format!(
                "unknown aggregate public output tag {tag}"
            )));
        }
    };
    input.finish("aggregate public output")?;
    Ok(decoded)
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_digest(out: &mut Vec<u8>, value: &Digest) {
    out.extend_from_slice(value);
}

struct AggregateDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> AggregateDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn expect_bytes(&mut self, name: &'static str, expected: &[u8]) -> ProofResult<()> {
        let actual = self.take(name, expected.len())?;
        if actual == expected {
            Ok(())
        } else {
            Err(ProofError::Codec(format!("invalid {name}")))
        }
    }

    fn read_u8(&mut self, name: &'static str) -> ProofResult<u8> {
        Ok(self.take(name, 1)?[0])
    }

    fn read_u32(&mut self, name: &'static str) -> ProofResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(name, 4)?
                .try_into()
                .expect("decoder returned exact u32 byte length"),
        ))
    }

    fn read_digest(&mut self, name: &'static str) -> ProofResult<Digest> {
        Ok(self
            .take(name, 32)?
            .try_into()
            .expect("decoder returned exact digest byte length"))
    }

    fn finish(&self, name: &'static str) -> ProofResult<()> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(ProofError::Codec(format!(
                "{name} had {} trailing bytes",
                self.bytes.len() - self.cursor
            )))
        }
    }

    fn take(&mut self, name: &'static str, len: usize) -> ProofResult<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| ProofError::Codec(format!("{name} length overflow")))?;
        if end > self.bytes.len() {
            return Err(ProofError::Codec(format!(
                "{name} ended early: wanted {len} bytes, remaining {}",
                self.bytes.len().saturating_sub(self.cursor)
            )));
        }
        let out = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_public_output;
    use crate::native_types::field_to_digest;
    use crate::public_output::{ProcessMessagesPublicOutput, PublicOutput, TallyVotesPublicOutput};

    #[test]
    fn process_messages_aggregate_links_children() {
        let first = process_messages_public_output(10, 20, 100, 200);
        let second = process_messages_public_output(20, 30, 200, 300);
        let children = vec![first, second];

        let aggregate = build_process_messages_aggregate_public_output(&children).unwrap();

        assert_eq!(aggregate.child_count, 2);
        assert_eq!(
            aggregate.initial_batch_start_hash,
            field_to_digest(&Field::from(10u32))
        );
        assert_eq!(
            aggregate.final_batch_end_hash,
            field_to_digest(&Field::from(30u32))
        );
        assert_eq!(
            aggregate.initial_state_commitment,
            field_to_digest(&Field::from(100u32))
        );
        assert_eq!(
            aggregate.final_state_commitment,
            field_to_digest(&Field::from(300u32))
        );

        let encoded =
            encode_aggregate_public_output(&AggregatePublicOutput::ProcessMessages(aggregate));
        let decoded = decode_aggregate_public_output(&encoded).unwrap();
        assert!(matches!(decoded, AggregatePublicOutput::ProcessMessages(_)));
    }

    #[test]
    fn process_messages_aggregate_rejects_broken_batch_chain() {
        let first = process_messages_public_output(10, 20, 100, 200);
        let second = process_messages_public_output(21, 30, 200, 300);
        let err = build_process_messages_aggregate_public_output(&[first, second]).unwrap_err();
        assert!(err.to_string().contains("batch hash chain"));
    }

    #[test]
    fn process_messages_aggregate_rejects_broken_state_chain() {
        let first = process_messages_public_output(10, 20, 100, 200);
        let second = process_messages_public_output(20, 30, 201, 300);
        let err = build_process_messages_aggregate_public_output(&[first, second]).unwrap_err();
        assert!(err.to_string().contains("state commitment chain"));
    }

    #[test]
    fn tally_aggregate_links_children() {
        let first = tally_public_output(0, 6, 100, 0, 200);
        let second = tally_public_output(1, 6, 100, 200, 300);
        let children = vec![first, second];

        let aggregate = build_tally_aggregate_public_output(&children).unwrap();

        assert_eq!(aggregate.child_count, 2);
        assert_eq!(aggregate.first_batch_num, 0);
        assert_eq!(aggregate.last_batch_num, 1);
        assert_eq!(
            aggregate.state_commitment,
            field_to_digest(&Field::from(100u32))
        );
        assert_eq!(
            aggregate.initial_tally_commitment,
            field_to_digest(&Field::from(0u32))
        );
        assert_eq!(
            aggregate.final_tally_commitment,
            field_to_digest(&Field::from(300u32))
        );

        let encoded = encode_aggregate_public_output(&AggregatePublicOutput::Tally(aggregate));
        let decoded = decode_aggregate_public_output(&encoded).unwrap();
        assert!(matches!(decoded, AggregatePublicOutput::Tally(_)));
    }

    #[test]
    fn tally_aggregate_rejects_non_consecutive_batches() {
        let first = tally_public_output(0, 6, 100, 0, 200);
        let second = tally_public_output(2, 6, 100, 200, 300);
        let err = build_tally_aggregate_public_output(&[first, second]).unwrap_err();
        assert!(err.to_string().contains("batch_num"));
    }

    #[test]
    fn tally_aggregate_rejects_broken_commitment_chain() {
        let first = tally_public_output(0, 6, 100, 0, 200);
        let second = tally_public_output(1, 6, 100, 201, 300);
        let err = build_tally_aggregate_public_output(&[first, second]).unwrap_err();
        assert!(err.to_string().contains("current tally commitment"));
    }

    fn tally_public_output(
        batch_num: u32,
        num_signups: u32,
        state_commitment: u32,
        current_tally_commitment: u32,
        new_tally_commitment: u32,
    ) -> Vec<u8> {
        let packed_vals = (Field::from(num_signups) << 32usize) + Field::from(batch_num);
        encode_public_output(&PublicOutput::TallyVotes(TallyVotesPublicOutput {
            input_hash: field_to_digest(&Field::from(1u32)),
            packed_vals: field_to_digest(&packed_vals),
            state_commitment: field_to_digest(&Field::from(state_commitment)),
            current_tally_commitment: field_to_digest(&Field::from(current_tally_commitment)),
            new_tally_commitment: field_to_digest(&Field::from(new_tally_commitment)),
        }))
    }

    fn process_messages_public_output(
        batch_start_hash: u32,
        batch_end_hash: u32,
        current_state_commitment: u32,
        new_state_commitment: u32,
    ) -> Vec<u8> {
        let packed_vals = Field::from(5u32) + (Field::from(6u32) << 32usize);
        encode_public_output(&PublicOutput::ProcessMessages(
            ProcessMessagesPublicOutput {
                input_hash: field_to_digest(&Field::from(1u32)),
                packed_vals: field_to_digest(&packed_vals),
                coord_pub_key_hash: field_to_digest(&Field::from(2u32)),
                batch_start_hash: field_to_digest(&Field::from(batch_start_hash)),
                batch_end_hash: field_to_digest(&Field::from(batch_end_hash)),
                current_state_commitment: field_to_digest(&Field::from(current_state_commitment)),
                new_state_commitment: field_to_digest(&Field::from(new_state_commitment)),
                deactivate_commitment: field_to_digest(&Field::from(3u32)),
                expected_poll_id: field_to_digest(&Field::from(1u32)),
            },
        ))
    }
}
