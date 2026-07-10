use crate::aggregate::{
    build_process_messages_aggregate_public_output, build_tally_aggregate_public_output,
};
use crate::codec::decode_public_output;
use crate::error::{ProofError, ProofResult};
use crate::native_types::Digest;
use crate::public_output::PublicOutput;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

pub const TREE_FANOUT: usize = 5;
pub const TREE_AGGREGATE_MAGIC: &[u8; 8] = b"AMACITR2";

const TAG_PROCESS_MESSAGES: u8 = 1;
const TAG_TALLY: u8 = 2;
const TAG_ROUND_ROOT: u8 = 3;
const CHILD_KIND_BASE: u8 = 1;
const CHILD_KIND_TREE: u8 = 2;
const TREE_NODE_HASH_DOMAIN: &[u8] = b"AMACI_ZKVM_TREE_NODE_V2";

pub type MachineVkeyDigest = [u32; 8];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeProgramIdentity {
    pub base_program_vkey: Digest,
    pub tree_program_vkey: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeAggregateRequestKind {
    ProcessMessagesLeaf,
    ProcessMessagesInternal,
    TallyLeaf,
    TallyInternal,
    RoundRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeAggregateRequest {
    pub kind: TreeAggregateRequestKind,
    pub identity: TreeProgramIdentity,
    pub child_vkey_digests: Vec<MachineVkeyDigest>,
    pub child_public_outputs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeAggregatePublicOutput {
    ProcessMessages(ProcessMessagesTreePublicOutput),
    Tally(TallyTreePublicOutput),
    RoundRoot(RoundRootPublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMessagesTreePublicOutput {
    pub level: u32,
    pub direct_child_count: u32,
    pub leaf_count: u32,
    pub identity: TreeProgramIdentity,
    pub packed_vals: Digest,
    pub coord_pub_key_hash: Digest,
    pub initial_batch_start_hash: Digest,
    pub final_batch_end_hash: Digest,
    pub initial_state_commitment: Digest,
    pub final_state_commitment: Digest,
    pub deactivate_commitment: Digest,
    pub expected_poll_id: Digest,
    pub subtree_root: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyTreePublicOutput {
    pub level: u32,
    pub direct_child_count: u32,
    pub leaf_count: u32,
    pub identity: TreeProgramIdentity,
    pub first_batch_num: u32,
    pub last_batch_num: u32,
    pub state_commitment: Digest,
    pub initial_tally_commitment: Digest,
    pub final_tally_commitment: Digest,
    pub subtree_root: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundRootPublicOutput {
    pub direct_child_count: u32,
    pub total_leaf_count: u32,
    pub process_messages_leaf_count: u32,
    pub tally_leaf_count: u32,
    pub process_messages_level: u32,
    pub tally_level: u32,
    pub identity: TreeProgramIdentity,
    pub coord_pub_key_hash: Digest,
    pub expected_poll_id: Digest,
    pub new_deactivate_root: Digest,
    pub initial_batch_start_hash: Digest,
    pub final_batch_end_hash: Digest,
    pub initial_state_commitment: Digest,
    pub final_state_commitment: Digest,
    pub deactivate_commitment: Digest,
    pub initial_tally_commitment: Digest,
    pub final_tally_commitment: Digest,
    pub process_messages_subtree_root: Digest,
    pub tally_subtree_root: Digest,
    pub children_root: Digest,
}

pub fn machine_vkey_digest_bytes(words: &MachineVkeyDigest) -> Digest {
    let mut out = [0u8; 32];
    for (idx, word) in words.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn build_tree_request_output(
    request: &TreeAggregateRequest,
) -> ProofResult<TreeAggregatePublicOutput> {
    validate_request_shape(request)?;
    match request.kind {
        TreeAggregateRequestKind::ProcessMessagesLeaf => {
            validate_child_vkeys(request, ChildVkeyPattern::AllBase)?;
            Ok(TreeAggregatePublicOutput::ProcessMessages(
                build_process_messages_leaf(&request.child_public_outputs, &request.identity)?,
            ))
        }
        TreeAggregateRequestKind::ProcessMessagesInternal => {
            validate_child_vkeys(request, ChildVkeyPattern::AllTree)?;
            Ok(TreeAggregatePublicOutput::ProcessMessages(
                build_process_messages_internal(&request.child_public_outputs, &request.identity)?,
            ))
        }
        TreeAggregateRequestKind::TallyLeaf => {
            validate_child_vkeys(request, ChildVkeyPattern::AllBase)?;
            Ok(TreeAggregatePublicOutput::Tally(build_tally_leaf(
                &request.child_public_outputs,
                &request.identity,
            )?))
        }
        TreeAggregateRequestKind::TallyInternal => {
            validate_child_vkeys(request, ChildVkeyPattern::AllTree)?;
            Ok(TreeAggregatePublicOutput::Tally(build_tally_internal(
                &request.child_public_outputs,
                &request.identity,
            )?))
        }
        TreeAggregateRequestKind::RoundRoot => {
            validate_child_vkeys(request, ChildVkeyPattern::RoundRoot)?;
            Ok(TreeAggregatePublicOutput::RoundRoot(build_round_root(
                &request.child_public_outputs,
                &request.identity,
            )?))
        }
    }
}

pub fn encode_tree_public_output(output: &TreeAggregatePublicOutput) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(TREE_AGGREGATE_MAGIC);
    match output {
        TreeAggregatePublicOutput::ProcessMessages(output) => {
            out.push(TAG_PROCESS_MESSAGES);
            write_tree_header(
                &mut out,
                output.level,
                output.direct_child_count,
                output.leaf_count,
                &output.identity,
            );
            for digest in [
                &output.packed_vals,
                &output.coord_pub_key_hash,
                &output.initial_batch_start_hash,
                &output.final_batch_end_hash,
                &output.initial_state_commitment,
                &output.final_state_commitment,
                &output.deactivate_commitment,
                &output.expected_poll_id,
                &output.subtree_root,
            ] {
                write_digest(&mut out, digest);
            }
        }
        TreeAggregatePublicOutput::Tally(output) => {
            out.push(TAG_TALLY);
            write_tree_header(
                &mut out,
                output.level,
                output.direct_child_count,
                output.leaf_count,
                &output.identity,
            );
            write_u32(&mut out, output.first_batch_num);
            write_u32(&mut out, output.last_batch_num);
            for digest in [
                &output.state_commitment,
                &output.initial_tally_commitment,
                &output.final_tally_commitment,
                &output.subtree_root,
            ] {
                write_digest(&mut out, digest);
            }
        }
        TreeAggregatePublicOutput::RoundRoot(output) => {
            out.push(TAG_ROUND_ROOT);
            for value in [
                output.direct_child_count,
                output.total_leaf_count,
                output.process_messages_leaf_count,
                output.tally_leaf_count,
                output.process_messages_level,
                output.tally_level,
            ] {
                write_u32(&mut out, value);
            }
            write_identity(&mut out, &output.identity);
            for digest in [
                &output.coord_pub_key_hash,
                &output.expected_poll_id,
                &output.new_deactivate_root,
                &output.initial_batch_start_hash,
                &output.final_batch_end_hash,
                &output.initial_state_commitment,
                &output.final_state_commitment,
                &output.deactivate_commitment,
                &output.initial_tally_commitment,
                &output.final_tally_commitment,
                &output.process_messages_subtree_root,
                &output.tally_subtree_root,
                &output.children_root,
            ] {
                write_digest(&mut out, digest);
            }
        }
    }
    out
}

pub fn decode_tree_public_output(bytes: &[u8]) -> ProofResult<TreeAggregatePublicOutput> {
    let mut decoder = TreeDecoder::new(bytes);
    decoder.expect_bytes("tree aggregate magic", TREE_AGGREGATE_MAGIC)?;
    let tag = decoder.read_u8("tree aggregate tag")?;
    let output = match tag {
        TAG_PROCESS_MESSAGES => {
            let (level, direct_child_count, leaf_count, identity) = decoder.read_tree_header()?;
            TreeAggregatePublicOutput::ProcessMessages(ProcessMessagesTreePublicOutput {
                level,
                direct_child_count,
                leaf_count,
                identity,
                packed_vals: decoder.read_digest("packed vals")?,
                coord_pub_key_hash: decoder.read_digest("coordinator public key hash")?,
                initial_batch_start_hash: decoder.read_digest("initial batch start hash")?,
                final_batch_end_hash: decoder.read_digest("final batch end hash")?,
                initial_state_commitment: decoder.read_digest("initial state commitment")?,
                final_state_commitment: decoder.read_digest("final state commitment")?,
                deactivate_commitment: decoder.read_digest("deactivate commitment")?,
                expected_poll_id: decoder.read_digest("expected poll id")?,
                subtree_root: decoder.read_digest("subtree root")?,
            })
        }
        TAG_TALLY => {
            let (level, direct_child_count, leaf_count, identity) = decoder.read_tree_header()?;
            TreeAggregatePublicOutput::Tally(TallyTreePublicOutput {
                level,
                direct_child_count,
                leaf_count,
                identity,
                first_batch_num: decoder.read_u32("first batch number")?,
                last_batch_num: decoder.read_u32("last batch number")?,
                state_commitment: decoder.read_digest("state commitment")?,
                initial_tally_commitment: decoder.read_digest("initial tally commitment")?,
                final_tally_commitment: decoder.read_digest("final tally commitment")?,
                subtree_root: decoder.read_digest("subtree root")?,
            })
        }
        TAG_ROUND_ROOT => TreeAggregatePublicOutput::RoundRoot(RoundRootPublicOutput {
            direct_child_count: decoder.read_u32("direct child count")?,
            total_leaf_count: decoder.read_u32("total leaf count")?,
            process_messages_leaf_count: decoder.read_u32("process messages leaf count")?,
            tally_leaf_count: decoder.read_u32("tally leaf count")?,
            process_messages_level: decoder.read_u32("process messages level")?,
            tally_level: decoder.read_u32("tally level")?,
            identity: decoder.read_identity()?,
            coord_pub_key_hash: decoder.read_digest("coordinator public key hash")?,
            expected_poll_id: decoder.read_digest("expected poll id")?,
            new_deactivate_root: decoder.read_digest("new deactivate root")?,
            initial_batch_start_hash: decoder.read_digest("initial batch start hash")?,
            final_batch_end_hash: decoder.read_digest("final batch end hash")?,
            initial_state_commitment: decoder.read_digest("initial state commitment")?,
            final_state_commitment: decoder.read_digest("final state commitment")?,
            deactivate_commitment: decoder.read_digest("deactivate commitment")?,
            initial_tally_commitment: decoder.read_digest("initial tally commitment")?,
            final_tally_commitment: decoder.read_digest("final tally commitment")?,
            process_messages_subtree_root: decoder.read_digest("process messages subtree root")?,
            tally_subtree_root: decoder.read_digest("tally subtree root")?,
            children_root: decoder.read_digest("round children root")?,
        }),
        _ => {
            return Err(ProofError::Codec(format!(
                "unknown tree aggregate output tag {tag}"
            )))
        }
    };
    decoder.finish()?;
    Ok(output)
}

fn build_process_messages_leaf(
    children: &[Vec<u8>],
    identity: &TreeProgramIdentity,
) -> ProofResult<ProcessMessagesTreePublicOutput> {
    let aggregate = build_process_messages_aggregate_public_output(children)?;
    Ok(ProcessMessagesTreePublicOutput {
        level: 1,
        direct_child_count: count_u32("process messages direct child count", children.len())?,
        leaf_count: count_u32("process messages leaf count", children.len())?,
        identity: identity.clone(),
        packed_vals: aggregate.packed_vals,
        coord_pub_key_hash: aggregate.coord_pub_key_hash,
        initial_batch_start_hash: aggregate.initial_batch_start_hash,
        final_batch_end_hash: aggregate.final_batch_end_hash,
        initial_state_commitment: aggregate.initial_state_commitment,
        final_state_commitment: aggregate.final_state_commitment,
        deactivate_commitment: aggregate.deactivate_commitment,
        expected_poll_id: aggregate.expected_poll_id,
        subtree_root: tree_children_root(TAG_PROCESS_MESSAGES, 1, CHILD_KIND_BASE, children),
    })
}

fn build_process_messages_internal(
    children: &[Vec<u8>],
    identity: &TreeProgramIdentity,
) -> ProofResult<ProcessMessagesTreePublicOutput> {
    let mut decoded = Vec::with_capacity(children.len());
    for (idx, child) in children.iter().enumerate() {
        match decode_tree_public_output(child)? {
            TreeAggregatePublicOutput::ProcessMessages(output) => decoded.push(output),
            _ => {
                return Err(ProofError::Codec(format!(
                    "process messages tree child {idx} has the wrong stage"
                )))
            }
        }
    }
    let first = decoded
        .first()
        .expect("validated non-empty process messages children");
    if &first.identity != identity {
        return Err(ProofError::Codec(
            "process messages tree identity mismatch".to_string(),
        ));
    }
    let child_level = first.level;
    let mut leaf_count = 0u32;
    for (idx, child) in decoded.iter().enumerate() {
        if &child.identity != identity {
            return Err(ProofError::Codec(format!(
                "process messages tree child {idx} identity mismatch"
            )));
        }
        if child.level != child_level {
            return Err(ProofError::Codec(format!(
                "process messages tree child {idx} level mismatch"
            )));
        }
        if child.packed_vals != first.packed_vals
            || child.coord_pub_key_hash != first.coord_pub_key_hash
            || child.deactivate_commitment != first.deactivate_commitment
            || child.expected_poll_id != first.expected_poll_id
        {
            return Err(ProofError::Codec(format!(
                "process messages tree child {idx} round constants mismatch"
            )));
        }
        if idx > 0 {
            let previous = &decoded[idx - 1];
            if child.initial_batch_start_hash != previous.final_batch_end_hash {
                return Err(ProofError::Codec(format!(
                    "process messages tree child {idx} batch hash chain mismatch"
                )));
            }
            if child.initial_state_commitment != previous.final_state_commitment {
                return Err(ProofError::Codec(format!(
                    "process messages tree child {idx} state commitment chain mismatch"
                )));
            }
        }
        leaf_count = leaf_count
            .checked_add(child.leaf_count)
            .ok_or_else(|| ProofError::Codec("process messages leaf count overflow".to_string()))?;
    }
    Ok(ProcessMessagesTreePublicOutput {
        level: child_level
            .checked_add(1)
            .ok_or_else(|| ProofError::Codec("process messages tree level overflow".to_string()))?,
        direct_child_count: count_u32("process messages direct child count", children.len())?,
        leaf_count,
        identity: identity.clone(),
        packed_vals: first.packed_vals,
        coord_pub_key_hash: first.coord_pub_key_hash,
        initial_batch_start_hash: first.initial_batch_start_hash,
        final_batch_end_hash: decoded
            .last()
            .expect("validated non-empty process messages children")
            .final_batch_end_hash,
        initial_state_commitment: first.initial_state_commitment,
        final_state_commitment: decoded
            .last()
            .expect("validated non-empty process messages children")
            .final_state_commitment,
        deactivate_commitment: first.deactivate_commitment,
        expected_poll_id: first.expected_poll_id,
        subtree_root: tree_children_root(
            TAG_PROCESS_MESSAGES,
            child_level + 1,
            CHILD_KIND_TREE,
            children,
        ),
    })
}

fn build_tally_leaf(
    children: &[Vec<u8>],
    identity: &TreeProgramIdentity,
) -> ProofResult<TallyTreePublicOutput> {
    let aggregate = build_tally_aggregate_public_output(children)?;
    Ok(TallyTreePublicOutput {
        level: 1,
        direct_child_count: count_u32("tally direct child count", children.len())?,
        leaf_count: count_u32("tally leaf count", children.len())?,
        identity: identity.clone(),
        first_batch_num: aggregate.first_batch_num,
        last_batch_num: aggregate.last_batch_num,
        state_commitment: aggregate.state_commitment,
        initial_tally_commitment: aggregate.initial_tally_commitment,
        final_tally_commitment: aggregate.final_tally_commitment,
        subtree_root: tree_children_root(TAG_TALLY, 1, CHILD_KIND_BASE, children),
    })
}

fn build_tally_internal(
    children: &[Vec<u8>],
    identity: &TreeProgramIdentity,
) -> ProofResult<TallyTreePublicOutput> {
    let mut decoded = Vec::with_capacity(children.len());
    for (idx, child) in children.iter().enumerate() {
        match decode_tree_public_output(child)? {
            TreeAggregatePublicOutput::Tally(output) => decoded.push(output),
            _ => {
                return Err(ProofError::Codec(format!(
                    "tally tree child {idx} has the wrong stage"
                )))
            }
        }
    }
    let first = decoded.first().expect("validated non-empty tally children");
    if &first.identity != identity {
        return Err(ProofError::Codec(
            "tally tree identity mismatch".to_string(),
        ));
    }
    let child_level = first.level;
    let mut leaf_count = 0u32;
    for (idx, child) in decoded.iter().enumerate() {
        if &child.identity != identity {
            return Err(ProofError::Codec(format!(
                "tally tree child {idx} identity mismatch"
            )));
        }
        if child.level != child_level {
            return Err(ProofError::Codec(format!(
                "tally tree child {idx} level mismatch"
            )));
        }
        if child.state_commitment != first.state_commitment {
            return Err(ProofError::Codec(format!(
                "tally tree child {idx} state commitment mismatch"
            )));
        }
        if idx > 0 {
            let previous = &decoded[idx - 1];
            if child.first_batch_num != previous.last_batch_num.saturating_add(1) {
                return Err(ProofError::Codec(format!(
                    "tally tree child {idx} batch number mismatch"
                )));
            }
            if child.initial_tally_commitment != previous.final_tally_commitment {
                return Err(ProofError::Codec(format!(
                    "tally tree child {idx} tally commitment chain mismatch"
                )));
            }
        }
        leaf_count = leaf_count
            .checked_add(child.leaf_count)
            .ok_or_else(|| ProofError::Codec("tally leaf count overflow".to_string()))?;
    }
    Ok(TallyTreePublicOutput {
        level: child_level
            .checked_add(1)
            .ok_or_else(|| ProofError::Codec("tally tree level overflow".to_string()))?,
        direct_child_count: count_u32("tally direct child count", children.len())?,
        leaf_count,
        identity: identity.clone(),
        first_batch_num: first.first_batch_num,
        last_batch_num: decoded
            .last()
            .expect("validated non-empty tally children")
            .last_batch_num,
        state_commitment: first.state_commitment,
        initial_tally_commitment: first.initial_tally_commitment,
        final_tally_commitment: decoded
            .last()
            .expect("validated non-empty tally children")
            .final_tally_commitment,
        subtree_root: tree_children_root(TAG_TALLY, child_level + 1, CHILD_KIND_TREE, children),
    })
}

fn build_round_root(
    children: &[Vec<u8>],
    identity: &TreeProgramIdentity,
) -> ProofResult<RoundRootPublicOutput> {
    if children.len() != 4 {
        return Err(ProofError::InvalidLength {
            name: "round root children",
            expected: 4,
            actual: children.len(),
        });
    }
    let deactivate = match decode_public_output(&children[0])? {
        PublicOutput::ProcessDeactivate(output) => output,
        _ => {
            return Err(ProofError::Codec(
                "round child 0 is not process deactivate".to_string(),
            ))
        }
    };
    let add_key = match decode_public_output(&children[1])? {
        PublicOutput::AddNewKey(output) => output,
        _ => {
            return Err(ProofError::Codec(
                "round child 1 is not add new key".to_string(),
            ))
        }
    };
    let process_messages = match decode_tree_public_output(&children[2])? {
        TreeAggregatePublicOutput::ProcessMessages(output) => output,
        _ => {
            return Err(ProofError::Codec(
                "round child 2 is not process messages root".to_string(),
            ))
        }
    };
    let tally = match decode_tree_public_output(&children[3])? {
        TreeAggregatePublicOutput::Tally(output) => output,
        _ => {
            return Err(ProofError::Codec(
                "round child 3 is not tally root".to_string(),
            ))
        }
    };
    if process_messages.identity != *identity || tally.identity != *identity {
        return Err(ProofError::Codec(
            "round tree identity mismatch".to_string(),
        ));
    }
    if deactivate.new_deactivate_root != add_key.deactivate_root {
        return Err(ProofError::Codec(
            "round deactivate root did not link to add new key".to_string(),
        ));
    }
    if deactivate.coord_pub_key_hash != add_key.coord_pub_key_hash
        || deactivate.coord_pub_key_hash != process_messages.coord_pub_key_hash
    {
        return Err(ProofError::Codec(
            "round coordinator public key hash mismatch".to_string(),
        ));
    }
    if deactivate.expected_poll_id != add_key.poll_id
        || deactivate.expected_poll_id != process_messages.expected_poll_id
    {
        return Err(ProofError::Codec("round poll id mismatch".to_string()));
    }
    if process_messages.final_state_commitment != tally.state_commitment {
        return Err(ProofError::Codec(
            "round process messages state did not link to tally".to_string(),
        ));
    }
    if tally.first_batch_num != 0 || tally.last_batch_num.checked_add(1) != Some(tally.leaf_count) {
        return Err(ProofError::Codec(
            "round tally root does not cover batches from zero".to_string(),
        ));
    }
    let total_leaf_count = process_messages
        .leaf_count
        .checked_add(tally.leaf_count)
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| ProofError::Codec("round leaf count overflow".to_string()))?;
    Ok(RoundRootPublicOutput {
        direct_child_count: 4,
        total_leaf_count,
        process_messages_leaf_count: process_messages.leaf_count,
        tally_leaf_count: tally.leaf_count,
        process_messages_level: process_messages.level,
        tally_level: tally.level,
        identity: identity.clone(),
        coord_pub_key_hash: deactivate.coord_pub_key_hash,
        expected_poll_id: deactivate.expected_poll_id,
        new_deactivate_root: deactivate.new_deactivate_root,
        initial_batch_start_hash: process_messages.initial_batch_start_hash,
        final_batch_end_hash: process_messages.final_batch_end_hash,
        initial_state_commitment: process_messages.initial_state_commitment,
        final_state_commitment: process_messages.final_state_commitment,
        deactivate_commitment: process_messages.deactivate_commitment,
        initial_tally_commitment: tally.initial_tally_commitment,
        final_tally_commitment: tally.final_tally_commitment,
        process_messages_subtree_root: process_messages.subtree_root,
        tally_subtree_root: tally.subtree_root,
        children_root: tree_children_root(TAG_ROUND_ROOT, 0, CHILD_KIND_TREE, children),
    })
}

fn validate_request_shape(request: &TreeAggregateRequest) -> ProofResult<()> {
    let expected = request.child_public_outputs.len();
    if request.child_vkey_digests.len() != expected {
        return Err(ProofError::InvalidLength {
            name: "tree child vkey digests",
            expected,
            actual: request.child_vkey_digests.len(),
        });
    }
    if request.kind == TreeAggregateRequestKind::RoundRoot {
        if expected != 4 {
            return Err(ProofError::InvalidLength {
                name: "round root children",
                expected: 4,
                actual: expected,
            });
        }
    } else if expected == 0 || expected > TREE_FANOUT {
        return Err(ProofError::InvalidLength {
            name: "tree node children",
            expected: TREE_FANOUT,
            actual: expected,
        });
    }
    Ok(())
}

enum ChildVkeyPattern {
    AllBase,
    AllTree,
    RoundRoot,
}

fn validate_child_vkeys(
    request: &TreeAggregateRequest,
    pattern: ChildVkeyPattern,
) -> ProofResult<()> {
    for (idx, words) in request.child_vkey_digests.iter().enumerate() {
        let actual = machine_vkey_digest_bytes(words);
        let expected = match pattern {
            ChildVkeyPattern::AllBase => request.identity.base_program_vkey,
            ChildVkeyPattern::AllTree => request.identity.tree_program_vkey,
            ChildVkeyPattern::RoundRoot if idx < 2 => request.identity.base_program_vkey,
            ChildVkeyPattern::RoundRoot => request.identity.tree_program_vkey,
        };
        if actual != expected {
            return Err(ProofError::Codec(format!(
                "tree child {idx} program vkey mismatch"
            )));
        }
    }
    Ok(())
}

fn count_u32(name: &'static str, count: usize) -> ProofResult<u32> {
    count
        .try_into()
        .map_err(|_| ProofError::Codec(format!("{name} does not fit u32")))
}

fn tree_children_root(tag: u8, level: u32, child_kind: u8, children: &[Vec<u8>]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(TREE_NODE_HASH_DOMAIN);
    hasher.update([tag, child_kind]);
    hasher.update(level.to_be_bytes());
    hasher.update((children.len() as u64).to_be_bytes());
    for child in children {
        hasher.update((child.len() as u64).to_be_bytes());
        hasher.update(child);
    }
    hasher.finalize().into()
}

fn write_tree_header(
    out: &mut Vec<u8>,
    level: u32,
    direct_child_count: u32,
    leaf_count: u32,
    identity: &TreeProgramIdentity,
) {
    write_u32(out, level);
    write_u32(out, direct_child_count);
    write_u32(out, leaf_count);
    write_identity(out, identity);
}

fn write_identity(out: &mut Vec<u8>, identity: &TreeProgramIdentity) {
    write_digest(out, &identity.base_program_vkey);
    write_digest(out, &identity.tree_program_vkey);
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_digest(out: &mut Vec<u8>, value: &Digest) {
    out.extend_from_slice(value);
}

struct TreeDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TreeDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_bytes(&mut self, name: &str, expected: &[u8]) -> ProofResult<()> {
        let actual = self.read_exact(name, expected.len())?;
        if actual != expected {
            return Err(ProofError::Codec(format!("invalid {name}")));
        }
        Ok(())
    }

    fn read_u8(&mut self, name: &str) -> ProofResult<u8> {
        Ok(self.read_exact(name, 1)?[0])
    }

    fn read_u32(&mut self, name: &str) -> ProofResult<u32> {
        Ok(u32::from_be_bytes(
            self.read_exact(name, 4)?
                .try_into()
                .expect("read exact returned four bytes"),
        ))
    }

    fn read_digest(&mut self, name: &str) -> ProofResult<Digest> {
        Ok(self
            .read_exact(name, 32)?
            .try_into()
            .expect("read exact returned 32 bytes"))
    }

    fn read_identity(&mut self) -> ProofResult<TreeProgramIdentity> {
        Ok(TreeProgramIdentity {
            base_program_vkey: self.read_digest("base program vkey")?,
            tree_program_vkey: self.read_digest("tree program vkey")?,
        })
    }

    fn read_tree_header(&mut self) -> ProofResult<(u32, u32, u32, TreeProgramIdentity)> {
        Ok((
            self.read_u32("tree level")?,
            self.read_u32("direct child count")?,
            self.read_u32("leaf count")?,
            self.read_identity()?,
        ))
    }

    fn read_exact(&mut self, name: &str, len: usize) -> ProofResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| ProofError::Codec(format!("{name} offset overflow")))?;
        if end > self.bytes.len() {
            return Err(ProofError::Codec(format!("truncated {name}")));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn finish(self) -> ProofResult<()> {
        if self.offset != self.bytes.len() {
            return Err(ProofError::Codec(format!(
                "tree aggregate output has {} trailing bytes",
                self.bytes.len() - self.offset
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_public_output;
    use crate::public_output::{ProcessMessagesPublicOutput, TallyVotesPublicOutput};
    use crate::round_fixture::{fifteen_signup_round_fixture, fifty_signup_round_fixture};
    use crate::{execute_proof_logic, PublicOutput};

    fn digest(value: u8) -> Digest {
        [value; 32]
    }

    fn identity() -> TreeProgramIdentity {
        TreeProgramIdentity {
            base_program_vkey: machine_vkey_digest_bytes(&[1u32; 8]),
            tree_program_vkey: machine_vkey_digest_bytes(&[2u32; 8]),
        }
    }

    fn process_output(start: u8, end: u8, state_start: u8, state_end: u8) -> Vec<u8> {
        let mut packed_vals = [0u8; 32];
        packed_vals[24..].copy_from_slice(&((10u64 << 32) + 5).to_be_bytes());
        encode_public_output(&PublicOutput::ProcessMessages(
            ProcessMessagesPublicOutput {
                input_hash: digest(1),
                packed_vals,
                coord_pub_key_hash: digest(3),
                batch_start_hash: digest(start),
                batch_end_hash: digest(end),
                current_state_commitment: digest(state_start),
                new_state_commitment: digest(state_end),
                deactivate_commitment: digest(4),
                expected_poll_id: digest(5),
            },
        ))
    }

    fn tally_output(batch: u32, current: u8, new: u8) -> Vec<u8> {
        let mut packed = [0u8; 32];
        packed[27] = 10;
        packed[28..].copy_from_slice(&batch.to_be_bytes());
        encode_public_output(&PublicOutput::TallyVotes(TallyVotesPublicOutput {
            input_hash: digest(1),
            packed_vals: packed,
            state_commitment: digest(9),
            current_tally_commitment: digest(current),
            new_tally_commitment: digest(new),
        }))
    }

    #[test]
    fn process_messages_tree_roundtrips_and_links_levels() {
        let identity = identity();
        let leaf_a = build_process_messages_leaf(
            &[
                process_output(10, 11, 20, 21),
                process_output(11, 12, 21, 22),
            ],
            &identity,
        )
        .unwrap();
        let leaf_b = build_process_messages_leaf(
            &[
                process_output(12, 13, 22, 23),
                process_output(13, 14, 23, 24),
            ],
            &identity,
        )
        .unwrap();
        let children = vec![
            encode_tree_public_output(&TreeAggregatePublicOutput::ProcessMessages(leaf_a)),
            encode_tree_public_output(&TreeAggregatePublicOutput::ProcessMessages(leaf_b)),
        ];
        let root = build_process_messages_internal(&children, &identity).unwrap();
        assert_eq!(root.level, 2);
        assert_eq!(root.leaf_count, 4);
        let encoded = encode_tree_public_output(&TreeAggregatePublicOutput::ProcessMessages(root));
        assert_eq!(
            encode_tree_public_output(&decode_tree_public_output(&encoded).unwrap()),
            encoded
        );
    }

    #[test]
    fn tally_tree_rejects_non_consecutive_groups() {
        let identity = identity();
        let first = build_tally_leaf(&[tally_output(0, 0, 10)], &identity).unwrap();
        let second = build_tally_leaf(&[tally_output(2, 10, 20)], &identity).unwrap();
        let children = vec![
            encode_tree_public_output(&TreeAggregatePublicOutput::Tally(first)),
            encode_tree_public_output(&TreeAggregatePublicOutput::Tally(second)),
        ];
        let err = build_tally_internal(&children, &identity).unwrap_err();
        assert!(err.to_string().contains("batch number"));
    }

    #[test]
    fn request_rejects_more_than_five_children() {
        let request = TreeAggregateRequest {
            kind: TreeAggregateRequestKind::ProcessMessagesLeaf,
            identity: identity(),
            child_vkey_digests: vec![[1u32; 8]; 6],
            child_public_outputs: vec![process_output(0, 0, 0, 0); 6],
        };
        assert!(build_tree_request_output(&request).is_err());
    }

    #[test]
    fn request_rejects_child_program_identity_mismatch() {
        let request = TreeAggregateRequest {
            kind: TreeAggregateRequestKind::ProcessMessagesLeaf,
            identity: identity(),
            child_vkey_digests: vec![[9u32; 8]],
            child_public_outputs: vec![process_output(0, 1, 2, 3)],
        };
        let err = build_tree_request_output(&request).unwrap_err();
        assert!(err.to_string().contains("program vkey mismatch"));
    }

    #[test]
    fn fifteen_signup_round_builds_single_round_root() {
        let fixture = fifteen_signup_round_fixture().unwrap();
        let stage_outputs = fixture
            .stages
            .iter()
            .map(|stage| encode_public_output(&execute_proof_logic(&stage.input).unwrap()))
            .collect::<Vec<_>>();
        let identity = identity();
        let base_vkey = [1u32; 8];
        let tree_vkey = [2u32; 8];

        let process_request = TreeAggregateRequest {
            kind: TreeAggregateRequestKind::ProcessMessagesLeaf,
            identity: identity.clone(),
            child_vkey_digests: vec![base_vkey; 3],
            child_public_outputs: stage_outputs[2..5].to_vec(),
        };
        let process_root =
            encode_tree_public_output(&build_tree_request_output(&process_request).unwrap());

        let tally_request = TreeAggregateRequest {
            kind: TreeAggregateRequestKind::TallyLeaf,
            identity: identity.clone(),
            child_vkey_digests: vec![base_vkey; 4],
            child_public_outputs: stage_outputs[5..9].to_vec(),
        };
        let tally_root =
            encode_tree_public_output(&build_tree_request_output(&tally_request).unwrap());

        let round_request = TreeAggregateRequest {
            kind: TreeAggregateRequestKind::RoundRoot,
            identity,
            child_vkey_digests: vec![base_vkey, base_vkey, tree_vkey, tree_vkey],
            child_public_outputs: vec![
                stage_outputs[0].clone(),
                stage_outputs[1].clone(),
                process_root,
                tally_root,
            ],
        };
        let TreeAggregatePublicOutput::RoundRoot(root) =
            build_tree_request_output(&round_request).unwrap()
        else {
            panic!("request must produce a round root");
        };
        assert_eq!(root.process_messages_leaf_count, 3);
        assert_eq!(root.tally_leaf_count, 4);
        assert_eq!(root.total_leaf_count, 9);
        assert_eq!(root.direct_child_count, 4);
        let encoded = encode_tree_public_output(&TreeAggregatePublicOutput::RoundRoot(root));
        assert_eq!(encoded.len(), 513);
        assert!(matches!(
            decode_tree_public_output(&encoded).unwrap(),
            TreeAggregatePublicOutput::RoundRoot(_)
        ));
    }

    #[test]
    fn fifty_signup_round_builds_two_level_stage_trees() {
        let fixture = fifty_signup_round_fixture().unwrap();
        let stage_outputs = fixture
            .stages
            .iter()
            .map(|stage| encode_public_output(&execute_proof_logic(&stage.input).unwrap()))
            .collect::<Vec<_>>();
        let identity = identity();
        let base_vkey = [1u32; 8];
        let tree_vkey = [2u32; 8];

        let process_root = build_test_stage_tree(
            &stage_outputs[2..12],
            &identity,
            base_vkey,
            tree_vkey,
            TreeAggregateRequestKind::ProcessMessagesLeaf,
            TreeAggregateRequestKind::ProcessMessagesInternal,
        );
        let tally_root = build_test_stage_tree(
            &stage_outputs[12..23],
            &identity,
            base_vkey,
            tree_vkey,
            TreeAggregateRequestKind::TallyLeaf,
            TreeAggregateRequestKind::TallyInternal,
        );

        let TreeAggregatePublicOutput::ProcessMessages(process_summary) =
            decode_tree_public_output(&process_root).unwrap()
        else {
            panic!("process root must be process messages");
        };
        assert_eq!(process_summary.level, 2);
        assert_eq!(process_summary.leaf_count, 10);
        let TreeAggregatePublicOutput::Tally(tally_summary) =
            decode_tree_public_output(&tally_root).unwrap()
        else {
            panic!("tally root must be tally");
        };
        assert_eq!(tally_summary.level, 2);
        assert_eq!(tally_summary.leaf_count, 11);

        let request = TreeAggregateRequest {
            kind: TreeAggregateRequestKind::RoundRoot,
            identity,
            child_vkey_digests: vec![base_vkey, base_vkey, tree_vkey, tree_vkey],
            child_public_outputs: vec![
                stage_outputs[0].clone(),
                stage_outputs[1].clone(),
                process_root,
                tally_root,
            ],
        };
        let TreeAggregatePublicOutput::RoundRoot(root) =
            build_tree_request_output(&request).unwrap()
        else {
            panic!("request must produce a round root");
        };
        assert_eq!(root.process_messages_leaf_count, 10);
        assert_eq!(root.tally_leaf_count, 11);
        assert_eq!(root.total_leaf_count, 23);
        assert_eq!(root.process_messages_level, 2);
        assert_eq!(root.tally_level, 2);
    }

    fn build_test_stage_tree(
        base_outputs: &[Vec<u8>],
        identity: &TreeProgramIdentity,
        base_vkey: MachineVkeyDigest,
        tree_vkey: MachineVkeyDigest,
        leaf_kind: TreeAggregateRequestKind,
        internal_kind: TreeAggregateRequestKind,
    ) -> Vec<u8> {
        let mut current = base_outputs
            .chunks(TREE_FANOUT)
            .map(|children| {
                encode_tree_public_output(
                    &build_tree_request_output(&TreeAggregateRequest {
                        kind: leaf_kind,
                        identity: identity.clone(),
                        child_vkey_digests: vec![base_vkey; children.len()],
                        child_public_outputs: children.to_vec(),
                    })
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        while current.len() > 1 {
            current = current
                .chunks(TREE_FANOUT)
                .map(|children| {
                    encode_tree_public_output(
                        &build_tree_request_output(&TreeAggregateRequest {
                            kind: internal_kind,
                            identity: identity.clone(),
                            child_vkey_digests: vec![tree_vkey; children.len()],
                            child_public_outputs: children.to_vec(),
                        })
                        .unwrap(),
                    )
                })
                .collect();
        }
        current.pop().expect("test tree has a root")
    }
}
