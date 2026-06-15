use crate::circuits::{assert_input_hash, poseidon2};
use crate::error::{ProofError, ProofResult};
use crate::field::{pow5, Field};
use crate::merkle::{check_inclusion, check_root, state_leaf_hash, zero_root};
use crate::packing::unpack_tally_packed_vals;
use crate::public_output::TallyVotesPublicOutput;
use crate::types::TallyVotesInput;
use maci_crypto::poseidon;
use num_bigint::BigUint;
use num_traits::Zero;

/// Mirrors `amaci/power/tallyVotes.circom::TallyVotes`.
pub fn execute(input: &TallyVotesInput) -> ProofResult<TallyVotesPublicOutput> {
    if input.int_state_tree_depth >= input.state_tree_depth {
        return Err(ProofError::InvalidRange {
            name: "intStateTreeDepth",
            value: BigUint::from(input.int_state_tree_depth),
            max: BigUint::from(input.state_tree_depth - 1),
        });
    }

    let batch_size = pow5(5, input.int_state_tree_depth);
    let num_vote_options = pow5(5, input.vote_option_tree_depth);
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

    let state_commitment = poseidon2(&input.state_root, &input.state_salt);
    if state_commitment != input.state_commitment {
        return Err(ProofError::CommitmentMismatch {
            name: "stateCommitment",
            expected: state_commitment,
            actual: input.state_commitment.clone(),
        });
    }

    let packed = unpack_tally_packed_vals(&input.packed_vals)?;
    let batch_start_index = &packed.batch_num * BigUint::from(batch_size);
    if batch_start_index > packed.num_sign_ups {
        return Err(ProofError::InvalidRange {
            name: "batchStartIndex",
            value: batch_start_index,
            max: packed.num_sign_ups,
        });
    }

    let mut state_leaf_hashes = Vec::with_capacity(batch_size);
    for row in &input.state_leaf {
        state_leaf_hashes.push(state_leaf_hash(row)?);
    }
    let state_subroot = check_root(&state_leaf_hashes, input.int_state_tree_depth)?;
    let batch_num = packed.batch_num.clone();
    check_inclusion(
        "state subtree",
        &state_subroot,
        &batch_num,
        &input.state_path_elements,
        &input.state_root,
    )?;

    let vo_zero_root = zero_root(input.vote_option_tree_depth)?;
    for (i, (state, votes)) in input.state_leaf.iter().zip(input.votes.iter()).enumerate() {
        if votes.len() != num_vote_options {
            return Err(ProofError::InvalidLength {
                name: "vote row",
                expected: num_vote_options,
                actual: votes.len(),
            });
        }
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
    let current_tally_hash = poseidon2(&current_results_root, &input.current_results_root_salt);
    let expected_current_tally = if is_first_batch {
        BigUint::from(0u32)
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
    let expected_new_tally = poseidon(&[new_results_root, input.new_results_root_salt.clone()]);
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
        input_hash: input.input_hash.clone(),
        packed_vals: input.packed_vals.clone(),
        state_commitment: input.state_commitment.clone(),
        current_tally_commitment: input.current_tally_commitment.clone(),
        new_tally_commitment: input.new_tally_commitment.clone(),
    })
}

/// Mirrors the result accumulation and `ResultCommitmentVerifier` inputs.
fn tally_results(
    current_results: &[Field],
    votes: &[Vec<Field>],
    is_first_batch: bool,
    num_vote_options: usize,
) -> Vec<Field> {
    let max_votes = BigUint::from(10u32).pow(24);
    let mut out = if is_first_batch {
        vec![BigUint::from(0u32); num_vote_options]
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
