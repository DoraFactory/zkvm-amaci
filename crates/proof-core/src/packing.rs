use crate::error::ProofResult;
use crate::field::{ensure_bits, Field};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedCommand {
    pub nonce: Field,
    pub state_index: Field,
    pub vote_option_index: Field,
    pub new_vote_weight: Field,
    pub poll_id: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMessagesPackedVals {
    pub max_vote_options: Field,
    pub num_sign_ups: Field,
    pub is_quadratic_cost: Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyPackedVals {
    pub batch_num: Field,
    pub num_sign_ups: Field,
}

/// Splits a packed integer into high-to-low 32-bit chunks.
pub fn unpack_element_high_to_low(value: &Field, chunks: usize) -> ProofResult<Vec<Field>> {
    ensure_bits("packed element", value, chunks * 32)?;
    let mask = (Field::from(1u32) << 32usize) - Field::from(1u32);
    let mut out = Vec::with_capacity(chunks);
    for i in (0..chunks).rev() {
        out.push((*value >> (i * 32usize)) & mask);
    }
    Ok(out)
}

pub fn unpack_process_messages_packed_vals(
    packed_vals: &Field,
) -> ProofResult<ProcessMessagesPackedVals> {
    let chunks = unpack_element_high_to_low(packed_vals, 3)?;
    Ok(ProcessMessagesPackedVals {
        is_quadratic_cost: chunks[0].clone(),
        num_sign_ups: chunks[1].clone(),
        max_vote_options: chunks[2].clone(),
    })
}

pub fn unpack_tally_packed_vals(packed_vals: &Field) -> ProofResult<TallyPackedVals> {
    let chunks = unpack_element_high_to_low(packed_vals, 2)?;
    Ok(TallyPackedVals {
        num_sign_ups: chunks[0].clone(),
        batch_num: chunks[1].clone(),
    })
}

pub fn decode_vote_weight_96(high: &Field, mid: &Field, low: &Field) -> ProofResult<Field> {
    ensure_bits("vote weight high", high, 32)?;
    ensure_bits("vote weight mid", mid, 32)?;
    ensure_bits("vote weight low", low, 32)?;
    Ok(low
        + (mid * Field::from(4_294_967_296u64))
        + (high * Field::from(18_446_744_073_709_551_616u128)))
}

pub fn path_index_at(leaf_index: &Field, level: usize, base: usize) -> usize {
    let base_big = Field::from(base);
    ((*leaf_index / base_big.pow(Field::from(level as u32))) % base_big)
        .to_usize()
        .expect("path index is less than base and fits usize")
}
