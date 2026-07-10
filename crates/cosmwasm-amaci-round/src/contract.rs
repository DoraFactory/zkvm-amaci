use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;

use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, InstantiateMsg, QueryMsg, RoundStage, RoundStateResponse, TreeVerifierConfig,
};
use crate::state::{empty_completed_plan, plan_total, StoredRoundState, ROUND_STATE};

const AGGREGATE_MAGIC: &[u8; 8] = b"AMACIAG1";
const AGGREGATE_TAG_PROCESS_MESSAGES: u8 = 1;
const AGGREGATE_TAG_TALLY: u8 = 2;
const PROCESS_MESSAGES_AGGREGATE_PUBLIC_LEN: usize = 8 + 1 + 4 + 9 * 32;
const TALLY_AGGREGATE_PUBLIC_LEN: usize = 8 + 1 + 4 + 2 * 4 + 4 * 32;
const TREE_AGGREGATE_MAGIC: &[u8; 8] = b"AMACITR2";
const TREE_TAG_ROUND_ROOT: u8 = 3;
const TREE_ROUND_ROOT_PUBLIC_LEN: usize = 8 + 1 + 6 * 4 + 2 * 32 + 13 * 32;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    if plan_total(&msg.expected) == 0 {
        return Err(ContractError::EmptyRoundPlan);
    }
    if let Some(config) = &msg.tree_verifier {
        validate_tree_verifier_config(config)?;
    }

    let round_id = msg
        .round_id
        .unwrap_or_else(|| "zkvm-amaci-round-e2e".to_string());
    let state = StoredRoundState {
        round_id: round_id.clone(),
        expected: msg.expected,
        completed: empty_completed_plan(),
        verified_proofs: 0,
        tree_verifier: msg.tree_verifier,
    };
    ROUND_STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("round_id", round_id)
        .add_attribute("proof_mode", "sp1_compressed"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyCompressedStage {
            stage,
            proof,
            public_values,
            vkey_hash,
        } => execute_verify_compressed_stage(deps, stage, proof, public_values, vkey_hash),
        ExecuteMsg::VerifyCompressedAggregateStage {
            stage,
            proof,
            public_values,
            vkey_hash,
        } => {
            execute_verify_compressed_aggregate_stage(deps, stage, proof, public_values, vkey_hash)
        }
        ExecuteMsg::VerifyCompressedRoundRoot {
            proof,
            public_values,
        } => execute_verify_compressed_round_root(deps, proof, public_values),
    }
}

fn execute_verify_compressed_round_root(
    deps: DepsMut,
    proof: Binary,
    public_values: Binary,
) -> Result<Response, ContractError> {
    let mut state = ROUND_STATE.load(deps.storage)?;
    if plan_total(&state.completed) != 0 || state.verified_proofs != 0 {
        return Err(ContractError::RoundAlreadyStarted);
    }
    let config = state
        .tree_verifier
        .as_ref()
        .ok_or(ContractError::MissingTreeVerifierConfig)?;
    let root = decode_round_root_public_output(&public_values)?;

    if state.expected.process_deactivate != 1 || state.expected.add_new_key != 1 {
        return Err(ContractError::RoundRootPlanMismatch {
            reason:
                "round-root mode requires exactly one process-deactivate and one add-new-key proof"
                    .to_string(),
        });
    }
    if root.direct_child_count != 4 {
        return Err(ContractError::RoundRootPlanMismatch {
            reason: format!(
                "expected 4 direct round children, got {}",
                root.direct_child_count
            ),
        });
    }
    if root.process_messages_leaf_count != state.expected.process_messages {
        return Err(ContractError::RoundRootPlanMismatch {
            reason: format!(
                "process-messages leaf count {}, expected {}",
                root.process_messages_leaf_count, state.expected.process_messages
            ),
        });
    }
    if root.tally_leaf_count != state.expected.tally {
        return Err(ContractError::RoundRootPlanMismatch {
            reason: format!(
                "tally leaf count {}, expected {}",
                root.tally_leaf_count, state.expected.tally
            ),
        });
    }
    if root.total_leaf_count != plan_total(&state.expected) {
        return Err(ContractError::RoundRootPlanMismatch {
            reason: format!(
                "total leaf count {}, expected {}",
                root.total_leaf_count,
                plan_total(&state.expected)
            ),
        });
    }

    require_identity(
        "base_program_vkey_digest",
        &root.base_program_vkey_digest,
        &config.base_program_vkey_digest,
    )?;
    require_identity(
        "tree_program_vkey_digest",
        &root.tree_program_vkey_digest,
        &config.tree_program_vkey_digest,
    )?;
    require_identity(
        "expected_poll_id",
        &root.expected_poll_id,
        &config.expected_poll_id,
    )?;
    require_identity(
        "expected_coord_pub_key_hash",
        &root.coord_pub_key_hash,
        &config.expected_coord_pub_key_hash,
    )?;

    verify_sp1_compressed(&proof, &public_values, &config.tree_vkey_hash)?;
    state.completed = state.expected.clone();
    state.verified_proofs += 1;
    ROUND_STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "verify_compressed_round_root")
        .add_attribute("backend", "sp1")
        .add_attribute("proof_mode", "compressed_tree_round_root")
        .add_attribute("round_id", state.round_id)
        .add_attribute(
            "process_messages_leaf_count",
            root.process_messages_leaf_count.to_string(),
        )
        .add_attribute("tally_leaf_count", root.tally_leaf_count.to_string())
        .add_attribute("total_leaf_count", root.total_leaf_count.to_string())
        .add_attribute("verified_proofs", state.verified_proofs.to_string())
        .add_attribute("is_complete", "true"))
}

fn execute_verify_compressed_stage(
    deps: DepsMut,
    stage: RoundStage,
    proof: Binary,
    public_values: Binary,
    vkey_hash: Binary,
) -> Result<Response, ContractError> {
    let mut state = ROUND_STATE.load(deps.storage)?;
    let expected_stage = state.next_stage().ok_or(ContractError::RoundComplete)?;
    if expected_stage != stage {
        return Err(ContractError::StageOutOfOrder {
            expected: expected_stage,
            actual: stage,
        });
    }

    verify_sp1_compressed(&proof, &public_values, &vkey_hash)?;
    advance_stage(&mut state, &stage, 1);
    ROUND_STATE.save(deps.storage, &state)?;
    let is_complete = state.is_complete();

    Ok(Response::new()
        .add_attribute("method", "verify_compressed_stage")
        .add_attribute("backend", "sp1")
        .add_attribute("proof_mode", "compressed")
        .add_attribute("stage", stage.as_str())
        .add_attribute("round_id", state.round_id.clone())
        .add_attribute("verified_proofs", state.verified_proofs.to_string())
        .add_attribute("is_complete", is_complete.to_string()))
}

fn execute_verify_compressed_aggregate_stage(
    deps: DepsMut,
    stage: RoundStage,
    proof: Binary,
    public_values: Binary,
    vkey_hash: Binary,
) -> Result<Response, ContractError> {
    let mut state = ROUND_STATE.load(deps.storage)?;
    let expected_stage = state.next_stage().ok_or(ContractError::RoundComplete)?;
    if expected_stage != stage {
        return Err(ContractError::StageOutOfOrder {
            expected: expected_stage,
            actual: stage,
        });
    }
    if !matches!(stage, RoundStage::ProcessMessages | RoundStage::Tally) {
        return Err(ContractError::UnsupportedAggregateStage { stage });
    }

    let aggregate = decode_aggregate_public_output(&public_values)?;
    if aggregate.stage != stage {
        return Err(ContractError::AggregateStageMismatch {
            expected: stage,
            actual: aggregate.stage,
        });
    }
    let remaining = remaining_stage_count(&state, &stage);
    if aggregate.child_count == 0 || aggregate.child_count > remaining {
        return Err(ContractError::AggregateChildCountTooLarge {
            remaining,
            child_count: aggregate.child_count,
        });
    }

    verify_sp1_compressed(&proof, &public_values, &vkey_hash)?;
    advance_stage(&mut state, &stage, aggregate.child_count);
    ROUND_STATE.save(deps.storage, &state)?;
    let is_complete = state.is_complete();

    Ok(Response::new()
        .add_attribute("method", "verify_compressed_aggregate_stage")
        .add_attribute("backend", "sp1")
        .add_attribute("proof_mode", "compressed_aggregate")
        .add_attribute("stage", stage.as_str())
        .add_attribute("aggregate_child_count", aggregate.child_count.to_string())
        .add_attribute("round_id", state.round_id.clone())
        .add_attribute("verified_proofs", state.verified_proofs.to_string())
        .add_attribute("is_complete", is_complete.to_string()))
}

pub fn verify_sp1_compressed(
    proof: &[u8],
    public_values: &[u8],
    vkey_hash: &[u8],
) -> Result<(), ContractError> {
    SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, vkey_hash).map_err(
        |err| ContractError::CompressedVerification {
            reason: err.to_string(),
        },
    )
}

fn advance_stage(state: &mut StoredRoundState, stage: &RoundStage, count: u32) {
    match stage {
        RoundStage::ProcessDeactivate => state.completed.process_deactivate += count,
        RoundStage::AddNewKey => state.completed.add_new_key += count,
        RoundStage::ProcessMessages => state.completed.process_messages += count,
        RoundStage::Tally => state.completed.tally += count,
    }
    state.verified_proofs += 1;
}

fn remaining_stage_count(state: &StoredRoundState, stage: &RoundStage) -> u32 {
    match stage {
        RoundStage::ProcessDeactivate => state
            .expected
            .process_deactivate
            .saturating_sub(state.completed.process_deactivate),
        RoundStage::AddNewKey => state
            .expected
            .add_new_key
            .saturating_sub(state.completed.add_new_key),
        RoundStage::ProcessMessages => state
            .expected
            .process_messages
            .saturating_sub(state.completed.process_messages),
        RoundStage::Tally => state.expected.tally.saturating_sub(state.completed.tally),
    }
}

#[derive(Debug, Clone, PartialEq)]
struct AggregatePublicSummary {
    stage: RoundStage,
    child_count: u32,
}

fn decode_aggregate_public_output(bytes: &[u8]) -> Result<AggregatePublicSummary, ContractError> {
    if bytes.len() < AGGREGATE_MAGIC.len() + 1 + 4 {
        return Err(ContractError::InvalidAggregatePublicOutput {
            reason: "too short".to_string(),
        });
    }
    if &bytes[..AGGREGATE_MAGIC.len()] != AGGREGATE_MAGIC {
        return Err(ContractError::InvalidAggregatePublicOutput {
            reason: "invalid magic".to_string(),
        });
    }

    let tag = bytes[AGGREGATE_MAGIC.len()];
    let expected_len = match tag {
        AGGREGATE_TAG_PROCESS_MESSAGES => PROCESS_MESSAGES_AGGREGATE_PUBLIC_LEN,
        AGGREGATE_TAG_TALLY => TALLY_AGGREGATE_PUBLIC_LEN,
        _ => {
            return Err(ContractError::InvalidAggregatePublicOutput {
                reason: format!("unknown tag {tag}"),
            });
        }
    };
    if bytes.len() != expected_len {
        return Err(ContractError::InvalidAggregatePublicOutput {
            reason: format!("invalid length {}, expected {expected_len}", bytes.len()),
        });
    }

    let child_count_offset = AGGREGATE_MAGIC.len() + 1;
    let child_count = u32::from_be_bytes(
        bytes[child_count_offset..child_count_offset + 4]
            .try_into()
            .expect("slice length is exactly u32"),
    );
    let stage = match tag {
        AGGREGATE_TAG_PROCESS_MESSAGES => RoundStage::ProcessMessages,
        AGGREGATE_TAG_TALLY => RoundStage::Tally,
        _ => unreachable!("tag checked above"),
    };

    Ok(AggregatePublicSummary { stage, child_count })
}

#[derive(Debug, Clone, PartialEq)]
struct RoundRootPublicSummary {
    direct_child_count: u32,
    total_leaf_count: u32,
    process_messages_leaf_count: u32,
    tally_leaf_count: u32,
    base_program_vkey_digest: [u8; 32],
    tree_program_vkey_digest: [u8; 32],
    coord_pub_key_hash: [u8; 32],
    expected_poll_id: [u8; 32],
}

fn decode_round_root_public_output(bytes: &[u8]) -> Result<RoundRootPublicSummary, ContractError> {
    if bytes.len() != TREE_ROUND_ROOT_PUBLIC_LEN {
        return Err(ContractError::InvalidRoundRootPublicOutput {
            reason: format!(
                "invalid length {}, expected {TREE_ROUND_ROOT_PUBLIC_LEN}",
                bytes.len()
            ),
        });
    }
    if &bytes[..TREE_AGGREGATE_MAGIC.len()] != TREE_AGGREGATE_MAGIC {
        return Err(ContractError::InvalidRoundRootPublicOutput {
            reason: "invalid magic".to_string(),
        });
    }
    if bytes[TREE_AGGREGATE_MAGIC.len()] != TREE_TAG_ROUND_ROOT {
        return Err(ContractError::InvalidRoundRootPublicOutput {
            reason: format!(
                "invalid tag {}, expected {TREE_TAG_ROUND_ROOT}",
                bytes[TREE_AGGREGATE_MAGIC.len()]
            ),
        });
    }

    let mut offset = TREE_AGGREGATE_MAGIC.len() + 1;
    let direct_child_count = read_u32(bytes, &mut offset);
    let total_leaf_count = read_u32(bytes, &mut offset);
    let process_messages_leaf_count = read_u32(bytes, &mut offset);
    let tally_leaf_count = read_u32(bytes, &mut offset);
    let _process_messages_level = read_u32(bytes, &mut offset);
    let _tally_level = read_u32(bytes, &mut offset);
    let base_program_vkey_digest = read_digest(bytes, &mut offset);
    let tree_program_vkey_digest = read_digest(bytes, &mut offset);
    let coord_pub_key_hash = read_digest(bytes, &mut offset);
    let expected_poll_id = read_digest(bytes, &mut offset);

    Ok(RoundRootPublicSummary {
        direct_child_count,
        total_leaf_count,
        process_messages_leaf_count,
        tally_leaf_count,
        base_program_vkey_digest,
        tree_program_vkey_digest,
        coord_pub_key_hash,
        expected_poll_id,
    })
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    let value = u32::from_be_bytes(
        bytes[*offset..*offset + 4]
            .try_into()
            .expect("round-root length was validated"),
    );
    *offset += 4;
    value
}

fn read_digest(bytes: &[u8], offset: &mut usize) -> [u8; 32] {
    let value = bytes[*offset..*offset + 32]
        .try_into()
        .expect("round-root length was validated");
    *offset += 32;
    value
}

fn validate_tree_verifier_config(config: &TreeVerifierConfig) -> Result<(), ContractError> {
    for (field, value) in [
        ("tree_vkey_hash", &config.tree_vkey_hash),
        ("base_program_vkey_digest", &config.base_program_vkey_digest),
        ("tree_program_vkey_digest", &config.tree_program_vkey_digest),
        ("expected_poll_id", &config.expected_poll_id),
        (
            "expected_coord_pub_key_hash",
            &config.expected_coord_pub_key_hash,
        ),
    ] {
        if value.len() != 32 {
            return Err(ContractError::InvalidTreeVerifierConfig {
                field: field.to_string(),
                actual: value.len(),
            });
        }
    }
    Ok(())
}

fn require_identity(field: &str, actual: &[u8; 32], expected: &[u8]) -> Result<(), ContractError> {
    if actual.as_slice() != expected {
        return Err(ContractError::RoundRootIdentityMismatch {
            field: field.to_string(),
        });
    }
    Ok(())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::RoundState {} => {
            let state = ROUND_STATE.load(deps.storage)?;
            let next_stage = state.next_stage();
            let is_complete = next_stage.is_none();
            to_json_binary(&RoundStateResponse {
                round_id: state.round_id,
                expected: state.expected,
                completed: state.completed,
                next_stage,
                is_complete,
                verified_proofs: state.verified_proofs,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::RoundPlan;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    fn plan() -> RoundPlan {
        RoundPlan {
            process_deactivate: 1,
            add_new_key: 1,
            process_messages: 2,
            tally: 2,
        }
    }

    #[test]
    fn instantiate_sets_initial_round_state() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: Some("round-1".to_string()),
                expected: plan(),
                tree_verifier: None,
            },
        )
        .unwrap();

        let response = query(deps.as_ref(), mock_env(), QueryMsg::RoundState {}).unwrap();
        let state: RoundStateResponse = cosmwasm_std::from_json(response).unwrap();
        assert_eq!(state.round_id, "round-1");
        assert_eq!(state.next_stage, Some(RoundStage::ProcessDeactivate));
        assert!(!state.is_complete);
    }

    #[test]
    fn empty_round_plan_is_rejected() {
        let mut deps = mock_dependencies();
        let err = instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: RoundPlan {
                    process_deactivate: 0,
                    add_new_key: 0,
                    process_messages: 0,
                    tally: 0,
                },
                tree_verifier: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::EmptyRoundPlan));
    }

    #[test]
    fn wrong_stage_order_is_rejected_before_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: None,
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedStage {
                stage: RoundStage::ProcessMessages,
                proof: Binary::default(),
                public_values: Binary::default(),
                vkey_hash: Binary::default(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, ContractError::StageOutOfOrder { .. }));
    }

    #[test]
    fn empty_proof_is_rejected_for_expected_stage() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: None,
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedStage {
                stage: RoundStage::ProcessDeactivate,
                proof: Binary::default(),
                public_values: Binary::default(),
                vkey_hash: Binary::default(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, ContractError::CompressedVerification { .. }));
    }

    #[test]
    fn aggregate_rejects_unsupported_stage_before_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: None,
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedAggregateStage {
                stage: RoundStage::ProcessDeactivate,
                proof: Binary::default(),
                public_values: aggregate_public_values(RoundStage::ProcessMessages, 1),
                vkey_hash: Binary::default(),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ContractError::UnsupportedAggregateStage {
                stage: RoundStage::ProcessDeactivate
            }
        ));
    }

    #[test]
    fn aggregate_rejects_stage_mismatch_before_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: Some("aggregate-mismatch".to_string()),
                expected: RoundPlan {
                    process_deactivate: 0,
                    add_new_key: 0,
                    process_messages: 1,
                    tally: 1,
                },
                tree_verifier: None,
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedAggregateStage {
                stage: RoundStage::ProcessMessages,
                proof: Binary::default(),
                public_values: aggregate_public_values(RoundStage::Tally, 1),
                vkey_hash: Binary::default(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, ContractError::AggregateStageMismatch { .. }));
    }

    #[test]
    fn aggregate_rejects_child_count_larger_than_remaining_before_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: Some("aggregate-too-large".to_string()),
                expected: RoundPlan {
                    process_deactivate: 0,
                    add_new_key: 0,
                    process_messages: 1,
                    tally: 0,
                },
                tree_verifier: None,
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedAggregateStage {
                stage: RoundStage::ProcessMessages,
                proof: Binary::default(),
                public_values: aggregate_public_values(RoundStage::ProcessMessages, 2),
                vkey_hash: Binary::default(),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ContractError::AggregateChildCountTooLarge {
                remaining: 1,
                child_count: 2
            }
        ));
    }

    fn aggregate_public_values(stage: RoundStage, child_count: u32) -> Binary {
        let (tag, digest_count, extra_u32_count) = match stage {
            RoundStage::ProcessMessages => (AGGREGATE_TAG_PROCESS_MESSAGES, 9usize, 0usize),
            RoundStage::Tally => (AGGREGATE_TAG_TALLY, 4usize, 2usize),
            RoundStage::ProcessDeactivate | RoundStage::AddNewKey => {
                (AGGREGATE_TAG_PROCESS_MESSAGES, 9usize, 0usize)
            }
        };
        let mut out = Vec::new();
        out.extend_from_slice(AGGREGATE_MAGIC);
        out.push(tag);
        out.extend_from_slice(&child_count.to_be_bytes());
        for _ in 0..extra_u32_count {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out.resize(out.len() + digest_count * 32, 0u8);
        Binary::from(out)
    }

    #[test]
    fn invalid_tree_verifier_config_is_rejected_at_instantiate() {
        let mut deps = mock_dependencies();
        let mut config = tree_verifier_config(7);
        config.tree_vkey_hash = Binary::from(vec![7u8; 31]);
        let err = instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: Some(config),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ContractError::InvalidTreeVerifierConfig { actual: 31, .. }
        ));
    }

    #[test]
    fn round_root_requires_pinned_verifier_config() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: None,
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedRoundRoot {
                proof: Binary::default(),
                public_values: round_root_public_values(2, 2, 7),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::MissingTreeVerifierConfig));
    }

    #[test]
    fn round_root_rejects_leaf_count_mismatch_before_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: Some(tree_verifier_config(7)),
            },
        )
        .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedRoundRoot {
                proof: Binary::default(),
                public_values: round_root_public_values(3, 2, 7),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RoundRootPlanMismatch { .. }));
    }

    #[test]
    fn round_root_rejects_program_identity_mismatch_before_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: Some(tree_verifier_config(7)),
            },
        )
        .unwrap();

        let mut public_values = round_root_public_values(2, 2, 7).to_vec();
        public_values[8 + 1 + 6 * 4] = 8;
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedRoundRoot {
                proof: Binary::default(),
                public_values: Binary::from(public_values),
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ContractError::RoundRootIdentityMismatch { field }
                if field == "base_program_vkey_digest"
        ));
    }

    #[test]
    fn round_root_is_rejected_after_partial_progress() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            InstantiateMsg {
                round_id: None,
                expected: plan(),
                tree_verifier: Some(tree_verifier_config(7)),
            },
        )
        .unwrap();
        ROUND_STATE
            .update(deps.as_mut().storage, |mut state| -> StdResult<_> {
                state.completed.process_deactivate = 1;
                Ok(state)
            })
            .unwrap();

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyCompressedRoundRoot {
                proof: Binary::default(),
                public_values: round_root_public_values(2, 2, 7),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RoundAlreadyStarted));
    }

    fn tree_verifier_config(fill: u8) -> TreeVerifierConfig {
        TreeVerifierConfig {
            tree_vkey_hash: Binary::from(vec![fill; 32]),
            base_program_vkey_digest: Binary::from(vec![fill; 32]),
            tree_program_vkey_digest: Binary::from(vec![fill; 32]),
            expected_poll_id: Binary::from(vec![fill; 32]),
            expected_coord_pub_key_hash: Binary::from(vec![fill; 32]),
        }
    }

    fn round_root_public_values(
        process_messages_leaf_count: u32,
        tally_leaf_count: u32,
        fill: u8,
    ) -> Binary {
        let mut out = Vec::with_capacity(TREE_ROUND_ROOT_PUBLIC_LEN);
        out.extend_from_slice(TREE_AGGREGATE_MAGIC);
        out.push(TREE_TAG_ROUND_ROOT);
        for value in [
            4,
            2 + process_messages_leaf_count + tally_leaf_count,
            process_messages_leaf_count,
            tally_leaf_count,
            1,
            1,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&[fill; 32]);
        out.extend_from_slice(&[fill; 32]);
        out.extend_from_slice(&[fill; 32]);
        out.extend_from_slice(&[fill; 32]);
        for _ in 0..11 {
            out.extend_from_slice(&[0u8; 32]);
        }
        assert_eq!(out.len(), TREE_ROUND_ROOT_PUBLIC_LEN);
        Binary::from(out)
    }
}
