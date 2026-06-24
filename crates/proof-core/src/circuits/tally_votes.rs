use crate::circuits::{assert_input_hash, hash2};
use crate::error::{ProofError, ProofResult};
use crate::field::{pow5, Field};
use crate::hash_backend::hash_pair;
use crate::merkle::{
    check_inclusion_digest, check_root, check_root_digest, state_leaf_hash_digest, zero_root,
};
use crate::native_types::field_to_digest;
use crate::packing::unpack_tally_packed_vals;
use crate::public_output::{public_value, TallyVotesPublicOutput};
use crate::types::{TallyVotesInput, VoteRow, VOTE_ROW_WORDS};

pub fn execute(input: &TallyVotesInput) -> ProofResult<TallyVotesPublicOutput> {
    if input.int_state_tree_depth >= input.state_tree_depth {
        return Err(ProofError::InvalidRange {
            name: "intStateTreeDepth",
            value: Field::from(input.int_state_tree_depth),
            max: Field::from(input.state_tree_depth - 1),
        });
    }

    let batch_size = pow5(5, input.int_state_tree_depth);
    let num_vote_options = pow5(5, input.vote_option_tree_depth);
    if num_vote_options != VOTE_ROW_WORDS {
        return Err(ProofError::InvalidLength {
            name: "vote option row width",
            expected: VOTE_ROW_WORDS,
            actual: num_vote_options,
        });
    }
    if input.state_leaf.len() != batch_size {
        return Err(ProofError::InvalidLength {
            name: "stateLeaf",
            expected: batch_size,
            actual: input.state_leaf.len(),
        });
    }
    if input.votes.len() != batch_size {
        return Err(ProofError::InvalidLength {
            name: "votes",
            expected: batch_size,
            actual: input.votes.len(),
        });
    }
    if input.current_results.len() != num_vote_options {
        return Err(ProofError::InvalidLength {
            name: "currentResults",
            expected: num_vote_options,
            actual: input.current_results.len(),
        });
    }

    let state_commitment = hash2(&input.state_root, &input.state_salt);
    if state_commitment != input.state_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "stateCommitment",
            expected: state_commitment,
            actual: input.state_commitment.clone(),
        });
    }

    let packed = unpack_tally_packed_vals(&input.packed_vals)?;
    let batch_start_index = &packed.batch_num * Field::from(batch_size);
    if batch_start_index > packed.num_sign_ups {
        return Err(ProofError::InvalidRange {
            name: "batchStartIndex",
            value: batch_start_index,
            max: packed.num_sign_ups,
        });
    }

    let mut state_leaf_hashes = Vec::with_capacity(batch_size);
    for row in &input.state_leaf {
        state_leaf_hashes.push(state_leaf_hash_digest(row)?);
    }
    let state_subroot = check_root_digest(&state_leaf_hashes, input.int_state_tree_depth)?;
    let batch_num = packed.batch_num.clone();
    check_inclusion_digest(
        "state subtree",
        &state_subroot,
        &batch_num,
        &input.state_path_elements,
        &field_to_digest(&input.state_root),
    )?;

    let vo_zero_root = zero_root(input.vote_option_tree_depth)?;
    for (i, (state, votes)) in input.state_leaf.iter().zip(input.votes.iter()).enumerate() {
        let vote_root = check_root(votes, input.vote_option_tree_depth)?;
        let state_vo_root = state[3].clone();
        let expected_vote_root = if state_vo_root.is_zero() {
            vo_zero_root.clone()
        } else {
            state_vo_root
        };
        if vote_root != expected_vote_root {
            return Err(ProofError::MerkleRootMismatch {
                name: "vote option root",
                expected: expected_vote_root,
                actual: vote_root,
            });
        }
        let _ = i;
    }

    let is_first_batch = batch_start_index.is_zero();
    let current_results_root = check_root(&input.current_results, input.vote_option_tree_depth)?;
    let current_tally_hash = hash2(&current_results_root, &input.current_results_root_salt);
    let expected_current_tally = if is_first_batch {
        Field::from(0u32)
    } else {
        current_tally_hash
    };
    if expected_current_tally != input.current_tally_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "currentTallyCommitment",
            expected: expected_current_tally,
            actual: input.current_tally_commitment.clone(),
        });
    }

    let new_results = tally_results(
        &input.current_results,
        &input.votes,
        is_first_batch,
        num_vote_options,
    );
    let new_results_root = check_root(&new_results, input.vote_option_tree_depth)?;
    let expected_new_tally = hash_pair(&new_results_root, &input.new_results_root_salt);
    if expected_new_tally != input.new_tally_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "newTallyCommitment",
            expected: expected_new_tally,
            actual: input.new_tally_commitment.clone(),
        });
    }

    assert_input_hash(
        &input.input_hash,
        &[
            input.packed_vals.clone(),
            input.state_commitment.clone(),
            input.current_tally_commitment.clone(),
            input.new_tally_commitment.clone(),
        ],
    )?;

    Ok(TallyVotesPublicOutput {
        input_hash: public_value(&input.input_hash),
        packed_vals: public_value(&input.packed_vals),
        state_commitment: public_value(&input.state_commitment),
        current_tally_commitment: public_value(&input.current_tally_commitment),
        new_tally_commitment: public_value(&input.new_tally_commitment),
    })
}

fn tally_results(
    current_results: &[Field],
    votes: &[VoteRow],
    is_first_batch: bool,
    num_vote_options: usize,
) -> Vec<Field> {
    let max_votes = Field::from(10u32).pow(Field::from(24u32));
    let mut out = if is_first_batch {
        vec![Field::from(0u32); num_vote_options]
    } else {
        current_results.to_vec()
    };
    for row in votes {
        for (i, vote) in row.iter().enumerate() {
            out[i] += vote * (vote + &max_votes);
        }
    }
    out
}
