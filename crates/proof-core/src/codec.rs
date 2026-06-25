use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::native_types::{field_to_digest, Digest};
use crate::public_output::{
    AddNewKeyPublicOutput, ProcessDeactivatePublicOutput, ProcessMessagesPublicOutput,
    TallyVotesPublicOutput,
};
use crate::types::{
    AddNewKeyInput, Message, PathElement, PathElements, ProcessDeactivateInput,
    ProcessMessagesInput, ProverInput, PubKey, StateLeaf, TallyVotesInput, VoteRow, VOTE_ROW_WORDS,
};
use crate::PublicOutput;

const INPUT_MAGIC: &[u8; 8] = b"AMACIZK1";
const PUBLIC_MAGIC: &[u8; 8] = b"AMACIPU1";
const TAG_PROCESS_MESSAGES: u8 = 1;
const TAG_TALLY_VOTES: u8 = 2;
const TAG_PROCESS_DEACTIVATE: u8 = 3;
const TAG_ADD_NEW_KEY: u8 = 4;

pub fn encode_input(input: &ProverInput) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(INPUT_MAGIC);
    match input {
        ProverInput::ProcessMessages(input) => {
            out.push(TAG_PROCESS_MESSAGES);
            encode_process_messages(&mut out, input);
        }
        ProverInput::TallyVotes(input) => {
            out.push(TAG_TALLY_VOTES);
            encode_tally_votes(&mut out, input);
        }
        ProverInput::ProcessDeactivate(input) => {
            out.push(TAG_PROCESS_DEACTIVATE);
            encode_process_deactivate(&mut out, input);
        }
        ProverInput::AddNewKey(input) => {
            out.push(TAG_ADD_NEW_KEY);
            encode_add_new_key(&mut out, input);
        }
    }
    out
}

pub fn decode_input(bytes: &[u8]) -> ProofResult<ProverInput> {
    let mut input = Decoder::new(bytes);
    input.expect_bytes("input codec magic", INPUT_MAGIC)?;
    let tag = input.read_u8("input tag")?;
    let decoded = match tag {
        TAG_PROCESS_MESSAGES => ProverInput::ProcessMessages(decode_process_messages(&mut input)?),
        TAG_TALLY_VOTES => ProverInput::TallyVotes(decode_tally_votes(&mut input)?),
        TAG_PROCESS_DEACTIVATE => {
            ProverInput::ProcessDeactivate(decode_process_deactivate(&mut input)?)
        }
        TAG_ADD_NEW_KEY => ProverInput::AddNewKey(decode_add_new_key(&mut input)?),
        _ => {
            return Err(ProofError::Codec(format!("unknown prover input tag {tag}")));
        }
    };
    input.finish("prover input")?;
    Ok(decoded)
}

pub fn encode_public_output(output: &PublicOutput) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PUBLIC_MAGIC);
    match output {
        PublicOutput::ProcessMessages(output) => {
            out.push(TAG_PROCESS_MESSAGES);
            encode_process_messages_public(&mut out, output);
        }
        PublicOutput::TallyVotes(output) => {
            out.push(TAG_TALLY_VOTES);
            encode_tally_votes_public(&mut out, output);
        }
        PublicOutput::ProcessDeactivate(output) => {
            out.push(TAG_PROCESS_DEACTIVATE);
            encode_process_deactivate_public(&mut out, output);
        }
        PublicOutput::AddNewKey(output) => {
            out.push(TAG_ADD_NEW_KEY);
            encode_add_new_key_public(&mut out, output);
        }
    }
    out
}

pub fn decode_public_output(bytes: &[u8]) -> ProofResult<PublicOutput> {
    let mut input = Decoder::new(bytes);
    input.expect_bytes("public codec magic", PUBLIC_MAGIC)?;
    let tag = input.read_u8("public output tag")?;
    let decoded = match tag {
        TAG_PROCESS_MESSAGES => {
            PublicOutput::ProcessMessages(decode_process_messages_public(&mut input)?)
        }
        TAG_TALLY_VOTES => PublicOutput::TallyVotes(decode_tally_votes_public(&mut input)?),
        TAG_PROCESS_DEACTIVATE => {
            PublicOutput::ProcessDeactivate(decode_process_deactivate_public(&mut input)?)
        }
        TAG_ADD_NEW_KEY => PublicOutput::AddNewKey(decode_add_new_key_public(&mut input)?),
        _ => {
            return Err(ProofError::Codec(format!(
                "unknown public output tag {tag}"
            )));
        }
    };
    input.finish("public output")?;
    Ok(decoded)
}

fn encode_process_messages_public(out: &mut Vec<u8>, output: &ProcessMessagesPublicOutput) {
    write_digest(out, &output.input_hash);
    write_digest(out, &output.packed_vals);
    write_digest(out, &output.coord_pub_key_hash);
    write_digest(out, &output.batch_start_hash);
    write_digest(out, &output.batch_end_hash);
    write_digest(out, &output.current_state_commitment);
    write_digest(out, &output.new_state_commitment);
    write_digest(out, &output.deactivate_commitment);
    write_digest(out, &output.expected_poll_id);
}

fn decode_process_messages_public(
    input: &mut Decoder<'_>,
) -> ProofResult<ProcessMessagesPublicOutput> {
    Ok(ProcessMessagesPublicOutput {
        input_hash: input.read_digest("inputHash")?,
        packed_vals: input.read_digest("packedVals")?,
        coord_pub_key_hash: input.read_digest("coordPubKeyHash")?,
        batch_start_hash: input.read_digest("batchStartHash")?,
        batch_end_hash: input.read_digest("batchEndHash")?,
        current_state_commitment: input.read_digest("currentStateCommitment")?,
        new_state_commitment: input.read_digest("newStateCommitment")?,
        deactivate_commitment: input.read_digest("deactivateCommitment")?,
        expected_poll_id: input.read_digest("expectedPollId")?,
    })
}

fn encode_tally_votes_public(out: &mut Vec<u8>, output: &TallyVotesPublicOutput) {
    write_digest(out, &output.input_hash);
    write_digest(out, &output.packed_vals);
    write_digest(out, &output.state_commitment);
    write_digest(out, &output.current_tally_commitment);
    write_digest(out, &output.new_tally_commitment);
}

fn decode_tally_votes_public(input: &mut Decoder<'_>) -> ProofResult<TallyVotesPublicOutput> {
    Ok(TallyVotesPublicOutput {
        input_hash: input.read_digest("inputHash")?,
        packed_vals: input.read_digest("packedVals")?,
        state_commitment: input.read_digest("stateCommitment")?,
        current_tally_commitment: input.read_digest("currentTallyCommitment")?,
        new_tally_commitment: input.read_digest("newTallyCommitment")?,
    })
}

fn encode_process_deactivate_public(out: &mut Vec<u8>, output: &ProcessDeactivatePublicOutput) {
    write_digest(out, &output.input_hash);
    write_digest(out, &output.new_deactivate_root);
    write_digest(out, &output.coord_pub_key_hash);
    write_digest(out, &output.batch_start_hash);
    write_digest(out, &output.batch_end_hash);
    write_digest(out, &output.current_deactivate_commitment);
    write_digest(out, &output.new_deactivate_commitment);
    write_digest(out, &output.current_state_root);
    write_digest(out, &output.expected_poll_id);
}

fn decode_process_deactivate_public(
    input: &mut Decoder<'_>,
) -> ProofResult<ProcessDeactivatePublicOutput> {
    Ok(ProcessDeactivatePublicOutput {
        input_hash: input.read_digest("inputHash")?,
        new_deactivate_root: input.read_digest("newDeactivateRoot")?,
        coord_pub_key_hash: input.read_digest("coordPubKeyHash")?,
        batch_start_hash: input.read_digest("batchStartHash")?,
        batch_end_hash: input.read_digest("batchEndHash")?,
        current_deactivate_commitment: input.read_digest("currentDeactivateCommitment")?,
        new_deactivate_commitment: input.read_digest("newDeactivateCommitment")?,
        current_state_root: input.read_digest("currentStateRoot")?,
        expected_poll_id: input.read_digest("expectedPollId")?,
    })
}

fn encode_add_new_key_public(out: &mut Vec<u8>, output: &AddNewKeyPublicOutput) {
    write_digest(out, &output.input_hash);
    write_digest(out, &output.deactivate_root);
    write_digest(out, &output.coord_pub_key_hash);
    write_digest(out, &output.nullifier);
    write_digest(out, &output.d1[0]);
    write_digest(out, &output.d1[1]);
    write_digest(out, &output.d2[0]);
    write_digest(out, &output.d2[1]);
    write_digest(out, &output.new_pub_key_hash);
    write_digest(out, &output.poll_id);
}

fn decode_add_new_key_public(input: &mut Decoder<'_>) -> ProofResult<AddNewKeyPublicOutput> {
    Ok(AddNewKeyPublicOutput {
        input_hash: input.read_digest("inputHash")?,
        deactivate_root: input.read_digest("deactivateRoot")?,
        coord_pub_key_hash: input.read_digest("coordPubKeyHash")?,
        nullifier: input.read_digest("nullifier")?,
        d1: [input.read_digest("d1")?, input.read_digest("d1")?],
        d2: [input.read_digest("d2")?, input.read_digest("d2")?],
        new_pub_key_hash: input.read_digest("newPubKeyHash")?,
        poll_id: input.read_digest("pollId")?,
    })
}

fn encode_process_messages(out: &mut Vec<u8>, input: &ProcessMessagesInput) {
    write_usize(out, input.state_tree_depth);
    write_usize(out, input.vote_option_tree_depth);
    write_usize(out, input.batch_size);
    write_field(out, &input.input_hash);
    write_field(out, &input.packed_vals);
    write_field(out, &input.expected_poll_id);
    write_field(out, &input.batch_start_hash);
    write_field(out, &input.batch_end_hash);
    write_field(out, &input.coord_priv_key);
    write_pub_key(out, &input.coord_pub_key);
    write_messages(out, &input.msgs);
    write_pub_keys(out, &input.enc_pub_keys);
    write_field(out, &input.current_state_root);
    write_state_leaves(out, &input.current_state_leaves);
    write_path_sets(out, &input.current_state_leaves_path_elements);
    write_field(out, &input.current_state_commitment);
    write_field(out, &input.current_state_salt);
    write_field(out, &input.new_state_commitment);
    write_field(out, &input.new_state_salt);
    write_field(out, &input.active_state_root);
    write_field(out, &input.deactivate_root);
    write_field(out, &input.deactivate_commitment);
    write_fields(out, &input.active_state_leaves);
    write_path_sets(out, &input.active_state_leaves_path_elements);
    write_fields(out, &input.current_vote_weights);
    write_path_sets(out, &input.current_vote_weights_path_elements);
}

fn decode_process_messages(input: &mut Decoder<'_>) -> ProofResult<ProcessMessagesInput> {
    Ok(ProcessMessagesInput {
        state_tree_depth: input.read_usize("stateTreeDepth")?,
        vote_option_tree_depth: input.read_usize("voteOptionTreeDepth")?,
        batch_size: input.read_usize("batchSize")?,
        input_hash: input.read_field("inputHash")?,
        packed_vals: input.read_field("packedVals")?,
        expected_poll_id: input.read_field("expectedPollId")?,
        batch_start_hash: input.read_field("batchStartHash")?,
        batch_end_hash: input.read_field("batchEndHash")?,
        coord_priv_key: input.read_field("coordPrivKey")?,
        coord_pub_key: input.read_pub_key("coordPubKey")?,
        msgs: input.read_messages("msgs")?,
        enc_pub_keys: input.read_pub_keys("encPubKeys")?,
        current_state_root: input.read_field("currentStateRoot")?,
        current_state_leaves: input.read_state_leaves("currentStateLeaves")?,
        current_state_leaves_path_elements: input
            .read_path_sets("currentStateLeavesPathElements")?,
        current_state_commitment: input.read_field("currentStateCommitment")?,
        current_state_salt: input.read_field("currentStateSalt")?,
        new_state_commitment: input.read_field("newStateCommitment")?,
        new_state_salt: input.read_field("newStateSalt")?,
        active_state_root: input.read_field("activeStateRoot")?,
        deactivate_root: input.read_field("deactivateRoot")?,
        deactivate_commitment: input.read_field("deactivateCommitment")?,
        active_state_leaves: input.read_fields("activeStateLeaves")?,
        active_state_leaves_path_elements: input.read_path_sets("activeStateLeavesPathElements")?,
        current_vote_weights: input.read_fields("currentVoteWeights")?,
        current_vote_weights_path_elements: input
            .read_path_sets("currentVoteWeightsPathElements")?,
    })
}

fn encode_tally_votes(out: &mut Vec<u8>, input: &TallyVotesInput) {
    write_usize(out, input.state_tree_depth);
    write_usize(out, input.int_state_tree_depth);
    write_usize(out, input.vote_option_tree_depth);
    write_field(out, &input.input_hash);
    write_field(out, &input.packed_vals);
    write_field(out, &input.state_root);
    write_field(out, &input.state_salt);
    write_field(out, &input.state_commitment);
    write_field(out, &input.current_tally_commitment);
    write_field(out, &input.new_tally_commitment);
    write_state_leaves(out, &input.state_leaf);
    write_path(out, &input.state_path_elements);
    write_vote_rows(out, &input.votes);
    write_fields(out, &input.current_results);
    write_field(out, &input.current_results_root_salt);
    write_field(out, &input.new_results_root_salt);
}

fn decode_tally_votes(input: &mut Decoder<'_>) -> ProofResult<TallyVotesInput> {
    Ok(TallyVotesInput {
        state_tree_depth: input.read_usize("stateTreeDepth")?,
        int_state_tree_depth: input.read_usize("intStateTreeDepth")?,
        vote_option_tree_depth: input.read_usize("voteOptionTreeDepth")?,
        input_hash: input.read_field("inputHash")?,
        packed_vals: input.read_field("packedVals")?,
        state_root: input.read_field("stateRoot")?,
        state_salt: input.read_field("stateSalt")?,
        state_commitment: input.read_field("stateCommitment")?,
        current_tally_commitment: input.read_field("currentTallyCommitment")?,
        new_tally_commitment: input.read_field("newTallyCommitment")?,
        state_leaf: input.read_state_leaves("stateLeaf")?,
        state_path_elements: input.read_path("statePathElements")?,
        votes: input.read_vote_rows("votes")?,
        current_results: input.read_fields("currentResults")?,
        current_results_root_salt: input.read_field("currentResultsRootSalt")?,
        new_results_root_salt: input.read_field("newResultsRootSalt")?,
    })
}

fn encode_process_deactivate(out: &mut Vec<u8>, input: &ProcessDeactivateInput) {
    write_usize(out, input.state_tree_depth);
    write_usize(out, input.batch_size);
    write_field(out, &input.input_hash);
    write_field(out, &input.expected_poll_id);
    write_field(out, &input.current_active_state_root);
    write_field(out, &input.current_deactivate_root);
    write_field(out, &input.batch_start_hash);
    write_field(out, &input.batch_end_hash);
    write_field(out, &input.coord_priv_key);
    write_pub_key(out, &input.coord_pub_key);
    write_messages(out, &input.msgs);
    write_pub_keys(out, &input.enc_pub_keys);
    write_pub_keys(out, &input.c1);
    write_pub_keys(out, &input.c2);
    write_fields(out, &input.current_active_state);
    write_fields(out, &input.new_active_state);
    write_field(out, &input.deactivate_index0);
    write_field(out, &input.current_state_root);
    write_state_leaves(out, &input.current_state_leaves);
    write_path_sets(out, &input.current_state_leaves_path_elements);
    write_path_sets(out, &input.active_state_leaves_path_elements);
    write_path_sets(out, &input.deactivate_leaves_path_elements);
    write_field(out, &input.current_deactivate_commitment);
    write_field(out, &input.new_deactivate_root);
    write_field(out, &input.new_deactivate_commitment);
}

fn decode_process_deactivate(input: &mut Decoder<'_>) -> ProofResult<ProcessDeactivateInput> {
    Ok(ProcessDeactivateInput {
        state_tree_depth: input.read_usize("stateTreeDepth")?,
        batch_size: input.read_usize("batchSize")?,
        input_hash: input.read_field("inputHash")?,
        expected_poll_id: input.read_field("expectedPollId")?,
        current_active_state_root: input.read_field("currentActiveStateRoot")?,
        current_deactivate_root: input.read_field("currentDeactivateRoot")?,
        batch_start_hash: input.read_field("batchStartHash")?,
        batch_end_hash: input.read_field("batchEndHash")?,
        coord_priv_key: input.read_field("coordPrivKey")?,
        coord_pub_key: input.read_pub_key("coordPubKey")?,
        msgs: input.read_messages("msgs")?,
        enc_pub_keys: input.read_pub_keys("encPubKeys")?,
        c1: input.read_pub_keys("c1")?,
        c2: input.read_pub_keys("c2")?,
        current_active_state: input.read_fields("currentActiveState")?,
        new_active_state: input.read_fields("newActiveState")?,
        deactivate_index0: input.read_field("deactivateIndex0")?,
        current_state_root: input.read_field("currentStateRoot")?,
        current_state_leaves: input.read_state_leaves("currentStateLeaves")?,
        current_state_leaves_path_elements: input
            .read_path_sets("currentStateLeavesPathElements")?,
        active_state_leaves_path_elements: input.read_path_sets("activeStateLeavesPathElements")?,
        deactivate_leaves_path_elements: input.read_path_sets("deactivateLeavesPathElements")?,
        current_deactivate_commitment: input.read_field("currentDeactivateCommitment")?,
        new_deactivate_root: input.read_field("newDeactivateRoot")?,
        new_deactivate_commitment: input.read_field("newDeactivateCommitment")?,
    })
}

fn encode_add_new_key(out: &mut Vec<u8>, input: &AddNewKeyInput) {
    write_usize(out, input.state_tree_depth);
    write_field(out, &input.input_hash);
    write_pub_key(out, &input.coord_pub_key);
    write_field(out, &input.deactivate_root);
    write_field(out, &input.deactivate_index);
    write_field(out, &input.deactivate_leaf);
    write_pub_key(out, &input.c1);
    write_pub_key(out, &input.c2);
    write_field(out, &input.random_val);
    write_pub_key(out, &input.d1);
    write_pub_key(out, &input.d2);
    write_path(out, &input.deactivate_leaf_path_elements);
    write_field(out, &input.nullifier);
    write_field(out, &input.old_private_key);
    write_pub_key(out, &input.new_pub_key);
    write_field(out, &input.poll_id);
}

fn decode_add_new_key(input: &mut Decoder<'_>) -> ProofResult<AddNewKeyInput> {
    Ok(AddNewKeyInput {
        state_tree_depth: input.read_usize("stateTreeDepth")?,
        input_hash: input.read_field("inputHash")?,
        coord_pub_key: input.read_pub_key("coordPubKey")?,
        deactivate_root: input.read_field("deactivateRoot")?,
        deactivate_index: input.read_field("deactivateIndex")?,
        deactivate_leaf: input.read_field("deactivateLeaf")?,
        c1: input.read_pub_key("c1")?,
        c2: input.read_pub_key("c2")?,
        random_val: input.read_field("randomVal")?,
        d1: input.read_pub_key("d1")?,
        d2: input.read_pub_key("d2")?,
        deactivate_leaf_path_elements: input.read_path("deactivateLeafPathElements")?,
        nullifier: input.read_field("nullifier")?,
        old_private_key: input.read_field("oldPrivateKey")?,
        new_pub_key: input.read_pub_key("newPubKey")?,
        poll_id: input.read_field("pollId")?,
    })
}

fn write_usize(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

fn write_field(out: &mut Vec<u8>, value: &Field) {
    out.extend_from_slice(&field_to_digest(value));
}

fn write_digest(out: &mut Vec<u8>, value: &Digest) {
    out.extend_from_slice(value);
}

fn write_pub_key(out: &mut Vec<u8>, value: &PubKey) {
    write_field(out, &value[0]);
    write_field(out, &value[1]);
}

fn write_fields(out: &mut Vec<u8>, values: &[Field]) {
    write_usize(out, values.len());
    for value in values {
        write_field(out, value);
    }
}

fn write_pub_keys(out: &mut Vec<u8>, values: &[PubKey]) {
    write_usize(out, values.len());
    for value in values {
        write_pub_key(out, value);
    }
}

fn write_message(out: &mut Vec<u8>, value: &Message) {
    for field in value {
        write_field(out, field);
    }
}

fn write_messages(out: &mut Vec<u8>, values: &[Message]) {
    write_usize(out, values.len());
    for value in values {
        write_message(out, value);
    }
}

fn write_state_leaf(out: &mut Vec<u8>, value: &StateLeaf) {
    for field in value {
        write_field(out, field);
    }
}

fn write_state_leaves(out: &mut Vec<u8>, values: &[StateLeaf]) {
    write_usize(out, values.len());
    for value in values {
        write_state_leaf(out, value);
    }
}

fn write_vote_row(out: &mut Vec<u8>, value: &VoteRow) {
    for field in value {
        write_field(out, field);
    }
}

fn write_vote_rows(out: &mut Vec<u8>, values: &[VoteRow]) {
    write_usize(out, values.len());
    for value in values {
        write_vote_row(out, value);
    }
}

fn write_path_element(out: &mut Vec<u8>, value: &PathElement) {
    for field in value {
        write_field(out, field);
    }
}

fn write_path(out: &mut Vec<u8>, value: &PathElements) {
    write_usize(out, value.len());
    for element in value {
        write_path_element(out, element);
    }
}

fn write_path_sets(out: &mut Vec<u8>, values: &[PathElements]) {
    write_usize(out, values.len());
    for value in values {
        write_path(out, value);
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn finish(&self, subject: &'static str) -> ProofResult<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ProofError::Codec(format!(
                "trailing {} bytes after {subject} decode",
                self.bytes.len() - self.pos
            )))
        }
    }

    fn expect_bytes(&mut self, name: &'static str, expected: &[u8]) -> ProofResult<()> {
        let actual = self.take(name, expected.len())?;
        if actual == expected {
            Ok(())
        } else {
            Err(ProofError::Codec(format!("{name} mismatch")))
        }
    }

    fn read_u8(&mut self, name: &'static str) -> ProofResult<u8> {
        Ok(self.take(name, 1)?[0])
    }

    fn read_usize(&mut self, name: &'static str) -> ProofResult<usize> {
        let bytes: [u8; 4] = self
            .take(name, 4)?
            .try_into()
            .expect("decoder returned exact u32 byte length");
        Ok(u32::from_be_bytes(bytes) as usize)
    }

    fn read_field(&mut self, name: &'static str) -> ProofResult<Field> {
        Ok(Field::from_be_bytes(self.read_digest(name)?))
    }

    fn read_digest(&mut self, name: &'static str) -> ProofResult<Digest> {
        Ok(self
            .take(name, 32)?
            .try_into()
            .expect("decoder returned exact digest byte length"))
    }

    fn read_pub_key(&mut self, name: &'static str) -> ProofResult<PubKey> {
        Ok([self.read_field(name)?, self.read_field(name)?])
    }

    fn read_fields(&mut self, name: &'static str) -> ProofResult<Vec<Field>> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_field(name)?);
        }
        Ok(out)
    }

    fn read_pub_keys(&mut self, name: &'static str) -> ProofResult<Vec<PubKey>> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_pub_key(name)?);
        }
        Ok(out)
    }

    fn read_message(&mut self, name: &'static str) -> ProofResult<Message> {
        let mut out = [Field::from(0u32); crate::types::MESSAGE_WORDS];
        for item in &mut out {
            *item = self.read_field(name)?;
        }
        Ok(out)
    }

    fn read_messages(&mut self, name: &'static str) -> ProofResult<Vec<Message>> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_message(name)?);
        }
        Ok(out)
    }

    fn read_state_leaf(&mut self, name: &'static str) -> ProofResult<StateLeaf> {
        let mut out = [Field::from(0u32); crate::types::STATE_LEAF_WORDS];
        for item in &mut out {
            *item = self.read_field(name)?;
        }
        Ok(out)
    }

    fn read_state_leaves(&mut self, name: &'static str) -> ProofResult<Vec<StateLeaf>> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_state_leaf(name)?);
        }
        Ok(out)
    }

    fn read_vote_row(&mut self, name: &'static str) -> ProofResult<VoteRow> {
        let mut out = [Field::from(0u32); VOTE_ROW_WORDS];
        for item in &mut out {
            *item = self.read_field(name)?;
        }
        Ok(out)
    }

    fn read_vote_rows(&mut self, name: &'static str) -> ProofResult<Vec<VoteRow>> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_vote_row(name)?);
        }
        Ok(out)
    }

    fn read_path_element(&mut self, name: &'static str) -> ProofResult<PathElement> {
        let mut out = [Field::from(0u32); 4];
        for item in &mut out {
            *item = self.read_field(name)?;
        }
        Ok(out)
    }

    fn read_path(&mut self, name: &'static str) -> ProofResult<PathElements> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_path_element(name)?);
        }
        Ok(out)
    }

    fn read_path_sets(&mut self, name: &'static str) -> ProofResult<Vec<PathElements>> {
        let len = self.read_usize(name)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_path(name)?);
        }
        Ok(out)
    }

    fn take(&mut self, name: &'static str, len: usize) -> ProofResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| ProofError::Codec(format!("{name} decode offset overflow")))?;
        if end > self.bytes.len() {
            return Err(ProofError::InvalidLength {
                name,
                expected: len,
                actual: self.bytes.len().saturating_sub(self.pos),
            });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }
}
