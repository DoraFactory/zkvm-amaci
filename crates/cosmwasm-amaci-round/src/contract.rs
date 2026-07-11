use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;

use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, InstantiateMsg, OnlineStateResponse, QueryMsg, RoundCheckpoint, RoundPhase,
    RoundStage, RoundStateResponse, VerifierConfig,
};
use crate::state::{
    empty_completed_plan, OnlineState, StoredRoundState, ROUND_STATE, USED_NULLIFIERS,
    VERIFIED_DEACTIVATE_ROOTS,
};

const PUBLIC_MAGIC: &[u8; 8] = b"AMACIPU1";
const TAG_PROCESS_DEACTIVATE: u8 = 3;
const TAG_ADD_NEW_KEY: u8 = 4;
const PROCESS_DEACTIVATE_PUBLIC_LEN: usize = 8 + 1 + 9 * 32;
const ADD_NEW_KEY_PUBLIC_LEN: usize = 8 + 1 + 10 * 32;

const TREE_MAGIC: &[u8; 8] = b"AMACITR3";
const TAG_FINALIZATION_ROOT: u8 = 3;
const FINALIZATION_ROOT_PUBLIC_LEN: usize = 8 + 1 + 6 * 4 + 14 * 32;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    validate_verifier_config(&msg.verifier)?;
    require_len(
        "initial_online_state.current_deactivate_commitment",
        &msg.initial_online_state.current_deactivate_commitment,
    )?;
    require_len(
        "initial_online_state.deactivate_batch_start_hash",
        &msg.initial_online_state.deactivate_batch_start_hash,
    )?;

    let round_id = msg
        .round_id
        .unwrap_or_else(|| "zkvm-amaci-round-e2e".to_string());
    let state = StoredRoundState {
        round_id: round_id.clone(),
        operator: info.sender.clone(),
        phase: RoundPhase::Open,
        expected: empty_completed_plan(),
        completed: empty_completed_plan(),
        verified_proofs: 0,
        verifier: msg.verifier,
        online: OnlineState {
            current_deactivate_commitment: msg.initial_online_state.current_deactivate_commitment,
            deactivate_batch_end_hash: msg.initial_online_state.deactivate_batch_start_hash,
            latest_deactivate_root: None,
            latest_state_root: None,
        },
        checkpoint: None,
    };
    ROUND_STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("round_id", round_id)
        .add_attribute("operator", info.sender)
        .add_attribute("phase", "open"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyOnlineProof {
            stage,
            proof,
            public_values,
        } => execute_verify_online_proof(deps, info, stage, proof, public_values),
        ExecuteMsg::CloseRound {
            process_messages_count,
            tally_count,
            initial_state_commitment,
            message_batch_start_hash,
            message_batch_end_hash,
        } => execute_close_round(
            deps,
            info,
            process_messages_count,
            tally_count,
            initial_state_commitment,
            message_batch_start_hash,
            message_batch_end_hash,
        ),
        ExecuteMsg::VerifyCompressedFinalizationRoot {
            proof,
            public_values,
        } => execute_verify_finalization_root(deps, proof, public_values),
    }
}

fn execute_verify_online_proof(
    deps: DepsMut,
    info: MessageInfo,
    stage: RoundStage,
    proof: Binary,
    public_values: Binary,
) -> Result<Response, ContractError> {
    let mut state = ROUND_STATE.load(deps.storage)?;
    require_phase(&state, RoundPhase::Open)?;
    if !matches!(stage, RoundStage::ProcessDeactivate | RoundStage::AddNewKey) {
        return Err(ContractError::UnsupportedOnlineStage { stage });
    }

    let output = decode_online_public_output(&public_values)?;
    match (stage.clone(), output) {
        (RoundStage::ProcessDeactivate, OnlinePublicOutput::ProcessDeactivate(output)) => {
            if info.sender != state.operator {
                return Err(ContractError::Unauthorized);
            }
            require_identity(
                "expected_coord_pub_key_hash",
                &output.coord_pub_key_hash,
                &state.verifier.expected_coord_pub_key_hash,
            )?;
            require_identity(
                "expected_poll_id",
                &output.expected_poll_id,
                &state.verifier.expected_poll_id,
            )?;
            require_transition(
                "current_deactivate_commitment",
                &output.current_deactivate_commitment,
                &state.online.current_deactivate_commitment,
            )?;
            require_transition(
                "deactivate_batch_start_hash",
                &output.batch_start_hash,
                &state.online.deactivate_batch_end_hash,
            )?;

            verify_sp1_compressed(&proof, &public_values, &state.verifier.base_vkey_hash)?;
            VERIFIED_DEACTIVATE_ROOTS.save(
                deps.storage,
                output.new_deactivate_root.as_slice(),
                &true,
            )?;
            state.online.current_deactivate_commitment = output.new_deactivate_commitment;
            state.online.deactivate_batch_end_hash = output.batch_end_hash;
            state.online.latest_deactivate_root = Some(output.new_deactivate_root);
            state.online.latest_state_root = Some(output.current_state_root);
            state.completed.process_deactivate =
                state.completed.process_deactivate.checked_add(1).ok_or(
                    ContractError::OnlineCounterOverflow {
                        stage: stage.clone(),
                    },
                )?;
        }
        (RoundStage::AddNewKey, OnlinePublicOutput::AddNewKey(output)) => {
            require_identity(
                "expected_coord_pub_key_hash",
                &output.coord_pub_key_hash,
                &state.verifier.expected_coord_pub_key_hash,
            )?;
            require_identity(
                "expected_poll_id",
                &output.poll_id,
                &state.verifier.expected_poll_id,
            )?;
            if !VERIFIED_DEACTIVATE_ROOTS
                .may_load(deps.storage, output.deactivate_root.as_slice())?
                .unwrap_or(false)
            {
                return Err(ContractError::UnknownDeactivateRoot);
            }
            if USED_NULLIFIERS
                .may_load(deps.storage, output.nullifier.as_slice())?
                .unwrap_or(false)
            {
                return Err(ContractError::NullifierAlreadyUsed);
            }

            verify_sp1_compressed(&proof, &public_values, &state.verifier.base_vkey_hash)?;
            USED_NULLIFIERS.save(deps.storage, output.nullifier.as_slice(), &true)?;
            state.completed.add_new_key = state.completed.add_new_key.checked_add(1).ok_or(
                ContractError::OnlineCounterOverflow {
                    stage: stage.clone(),
                },
            )?;
        }
        (expected, actual) => {
            return Err(ContractError::PublicOutputStageMismatch {
                expected,
                actual: actual.stage(),
            })
        }
    }

    state.verified_proofs += 1;
    ROUND_STATE.save(deps.storage, &state)?;
    Ok(Response::new()
        .add_attribute("method", "verify_online_proof")
        .add_attribute("stage", stage.as_str())
        .add_attribute("round_id", state.round_id)
        .add_attribute("phase", "open")
        .add_attribute("verified_proofs", state.verified_proofs.to_string()))
}

fn execute_close_round(
    deps: DepsMut,
    info: MessageInfo,
    process_messages_count: u32,
    tally_count: u32,
    initial_state_commitment: Binary,
    message_batch_start_hash: Binary,
    message_batch_end_hash: Binary,
) -> Result<Response, ContractError> {
    let mut state = ROUND_STATE.load(deps.storage)?;
    require_phase(&state, RoundPhase::Open)?;
    if info.sender != state.operator {
        return Err(ContractError::Unauthorized);
    }
    if process_messages_count == 0 || tally_count == 0 {
        return Err(ContractError::InvalidRoundPlan);
    }
    require_len("initial_state_commitment", &initial_state_commitment)?;
    require_len("message_batch_start_hash", &message_batch_start_hash)?;
    require_len("message_batch_end_hash", &message_batch_end_hash)?;

    state.expected.process_deactivate = state.completed.process_deactivate;
    state.expected.add_new_key = state.completed.add_new_key;
    state.expected.process_messages = process_messages_count;
    state.expected.tally = tally_count;
    state.checkpoint = Some(RoundCheckpoint {
        initial_state_commitment,
        message_batch_start_hash,
        message_batch_end_hash,
        deactivate_commitment: state.online.current_deactivate_commitment.clone(),
    });
    state.phase = RoundPhase::Closed;
    ROUND_STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "close_round")
        .add_attribute("round_id", state.round_id)
        .add_attribute("phase", "closed"))
}

fn execute_verify_finalization_root(
    deps: DepsMut,
    proof: Binary,
    public_values: Binary,
) -> Result<Response, ContractError> {
    let mut state = ROUND_STATE.load(deps.storage)?;
    require_phase(&state, RoundPhase::Closed)?;
    let root = decode_finalization_public_output(&public_values)?;
    let checkpoint = state
        .checkpoint
        .as_ref()
        .expect("closed round always has a checkpoint");

    if root.direct_child_count != 2 {
        return Err(ContractError::FinalizationPlanMismatch {
            reason: format!("expected 2 stage roots, got {}", root.direct_child_count),
        });
    }
    if root.process_messages_leaf_count != state.expected.process_messages
        || root.tally_leaf_count != state.expected.tally
        || root.total_leaf_count
            != state
                .expected
                .process_messages
                .saturating_add(state.expected.tally)
    {
        return Err(ContractError::FinalizationPlanMismatch {
            reason: "stage leaf counts do not match the round plan".to_string(),
        });
    }
    for (field, actual, expected) in [
        (
            "base_program_vkey_digest",
            &root.base_program_vkey_digest,
            &state.verifier.base_program_vkey_digest,
        ),
        (
            "tree_program_vkey_digest",
            &root.tree_program_vkey_digest,
            &state.verifier.tree_program_vkey_digest,
        ),
        (
            "expected_poll_id",
            &root.expected_poll_id,
            &state.verifier.expected_poll_id,
        ),
        (
            "expected_coord_pub_key_hash",
            &root.coord_pub_key_hash,
            &state.verifier.expected_coord_pub_key_hash,
        ),
    ] {
        require_identity(field, actual, expected)?;
    }
    for (field, actual, expected) in [
        (
            "initial_state_commitment",
            &root.initial_state_commitment,
            &checkpoint.initial_state_commitment,
        ),
        (
            "message_batch_start_hash",
            &root.initial_batch_start_hash,
            &checkpoint.message_batch_start_hash,
        ),
        (
            "message_batch_end_hash",
            &root.final_batch_end_hash,
            &checkpoint.message_batch_end_hash,
        ),
        (
            "deactivate_commitment",
            &root.deactivate_commitment,
            &checkpoint.deactivate_commitment,
        ),
    ] {
        if actual.as_slice() != expected.as_slice() {
            return Err(ContractError::FinalizationCheckpointMismatch {
                field: field.to_string(),
            });
        }
    }

    verify_sp1_compressed(&proof, &public_values, &state.verifier.tree_vkey_hash)?;
    state.completed.process_messages = state.expected.process_messages;
    state.completed.tally = state.expected.tally;
    state.verified_proofs += 1;
    state.phase = RoundPhase::Finalized;
    ROUND_STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "verify_compressed_finalization_root")
        .add_attribute("round_id", state.round_id)
        .add_attribute("phase", "finalized")
        .add_attribute(
            "process_messages_leaf_count",
            root.process_messages_leaf_count.to_string(),
        )
        .add_attribute("tally_leaf_count", root.tally_leaf_count.to_string())
        .add_attribute("verified_proofs", state.verified_proofs.to_string())
        .add_attribute("is_complete", "true"))
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

#[derive(Debug, Clone)]
enum OnlinePublicOutput {
    ProcessDeactivate(ProcessDeactivateSummary),
    AddNewKey(AddNewKeySummary),
}

impl OnlinePublicOutput {
    fn stage(&self) -> RoundStage {
        match self {
            Self::ProcessDeactivate(_) => RoundStage::ProcessDeactivate,
            Self::AddNewKey(_) => RoundStage::AddNewKey,
        }
    }
}

#[derive(Debug, Clone)]
struct ProcessDeactivateSummary {
    new_deactivate_root: Binary,
    coord_pub_key_hash: Binary,
    batch_start_hash: Binary,
    batch_end_hash: Binary,
    current_deactivate_commitment: Binary,
    new_deactivate_commitment: Binary,
    current_state_root: Binary,
    expected_poll_id: Binary,
}

#[derive(Debug, Clone)]
struct AddNewKeySummary {
    deactivate_root: Binary,
    coord_pub_key_hash: Binary,
    nullifier: Binary,
    poll_id: Binary,
}

fn decode_online_public_output(bytes: &[u8]) -> Result<OnlinePublicOutput, ContractError> {
    if bytes.len() < PUBLIC_MAGIC.len() + 1 || &bytes[..PUBLIC_MAGIC.len()] != PUBLIC_MAGIC {
        return Err(ContractError::InvalidPublicOutput {
            reason: "invalid base public output magic".to_string(),
        });
    }
    let tag = bytes[PUBLIC_MAGIC.len()];
    let expected_len = match tag {
        TAG_PROCESS_DEACTIVATE => PROCESS_DEACTIVATE_PUBLIC_LEN,
        TAG_ADD_NEW_KEY => ADD_NEW_KEY_PUBLIC_LEN,
        _ => {
            return Err(ContractError::InvalidPublicOutput {
                reason: format!("unsupported online public output tag {tag}"),
            })
        }
    };
    if bytes.len() != expected_len {
        return Err(ContractError::InvalidPublicOutput {
            reason: format!("invalid length {}, expected {expected_len}", bytes.len()),
        });
    }

    let mut offset = PUBLIC_MAGIC.len() + 1;
    let _input_hash = read_digest(bytes, &mut offset);
    Ok(match tag {
        TAG_PROCESS_DEACTIVATE => OnlinePublicOutput::ProcessDeactivate(ProcessDeactivateSummary {
            new_deactivate_root: read_digest(bytes, &mut offset),
            coord_pub_key_hash: read_digest(bytes, &mut offset),
            batch_start_hash: read_digest(bytes, &mut offset),
            batch_end_hash: read_digest(bytes, &mut offset),
            current_deactivate_commitment: read_digest(bytes, &mut offset),
            new_deactivate_commitment: read_digest(bytes, &mut offset),
            current_state_root: read_digest(bytes, &mut offset),
            expected_poll_id: read_digest(bytes, &mut offset),
        }),
        TAG_ADD_NEW_KEY => {
            let deactivate_root = read_digest(bytes, &mut offset);
            let coord_pub_key_hash = read_digest(bytes, &mut offset);
            let nullifier = read_digest(bytes, &mut offset);
            for _ in 0..5 {
                let _ = read_digest(bytes, &mut offset);
            }
            let poll_id = read_digest(bytes, &mut offset);
            OnlinePublicOutput::AddNewKey(AddNewKeySummary {
                deactivate_root,
                coord_pub_key_hash,
                nullifier,
                poll_id,
            })
        }
        _ => unreachable!("tag checked above"),
    })
}

#[derive(Debug, Clone)]
struct FinalizationPublicSummary {
    direct_child_count: u32,
    total_leaf_count: u32,
    process_messages_leaf_count: u32,
    tally_leaf_count: u32,
    base_program_vkey_digest: Binary,
    tree_program_vkey_digest: Binary,
    coord_pub_key_hash: Binary,
    expected_poll_id: Binary,
    initial_batch_start_hash: Binary,
    final_batch_end_hash: Binary,
    initial_state_commitment: Binary,
    deactivate_commitment: Binary,
}

fn decode_finalization_public_output(
    bytes: &[u8],
) -> Result<FinalizationPublicSummary, ContractError> {
    if bytes.len() != FINALIZATION_ROOT_PUBLIC_LEN {
        return Err(ContractError::InvalidPublicOutput {
            reason: format!(
                "invalid finalization length {}, expected {FINALIZATION_ROOT_PUBLIC_LEN}",
                bytes.len()
            ),
        });
    }
    if &bytes[..TREE_MAGIC.len()] != TREE_MAGIC || bytes[TREE_MAGIC.len()] != TAG_FINALIZATION_ROOT
    {
        return Err(ContractError::InvalidPublicOutput {
            reason: "invalid finalization root magic or tag".to_string(),
        });
    }
    let mut offset = TREE_MAGIC.len() + 1;
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
    let initial_batch_start_hash = read_digest(bytes, &mut offset);
    let final_batch_end_hash = read_digest(bytes, &mut offset);
    let initial_state_commitment = read_digest(bytes, &mut offset);
    let _final_state_commitment = read_digest(bytes, &mut offset);
    let deactivate_commitment = read_digest(bytes, &mut offset);

    Ok(FinalizationPublicSummary {
        direct_child_count,
        total_leaf_count,
        process_messages_leaf_count,
        tally_leaf_count,
        base_program_vkey_digest,
        tree_program_vkey_digest,
        coord_pub_key_hash,
        expected_poll_id,
        initial_batch_start_hash,
        final_batch_end_hash,
        initial_state_commitment,
        deactivate_commitment,
    })
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    let value = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    value
}

fn read_digest(bytes: &[u8], offset: &mut usize) -> Binary {
    let value = Binary::from(bytes[*offset..*offset + 32].to_vec());
    *offset += 32;
    value
}

fn validate_verifier_config(config: &VerifierConfig) -> Result<(), ContractError> {
    for (field, value) in [
        ("base_vkey_hash", &config.base_vkey_hash),
        ("tree_vkey_hash", &config.tree_vkey_hash),
        ("base_program_vkey_digest", &config.base_program_vkey_digest),
        ("tree_program_vkey_digest", &config.tree_program_vkey_digest),
        ("expected_poll_id", &config.expected_poll_id),
        (
            "expected_coord_pub_key_hash",
            &config.expected_coord_pub_key_hash,
        ),
    ] {
        require_len(field, value)?;
    }
    Ok(())
}

fn require_len(field: &str, value: &[u8]) -> Result<(), ContractError> {
    if value.len() != 32 {
        return Err(ContractError::InvalidConfigLength {
            field: field.to_string(),
            actual: value.len(),
        });
    }
    Ok(())
}

fn require_identity(field: &str, actual: &[u8], expected: &[u8]) -> Result<(), ContractError> {
    if actual != expected {
        return Err(ContractError::IdentityMismatch {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn require_transition(field: &str, actual: &[u8], expected: &[u8]) -> Result<(), ContractError> {
    if actual != expected {
        return Err(ContractError::DeactivateTransitionMismatch {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn require_phase(state: &StoredRoundState, expected: RoundPhase) -> Result<(), ContractError> {
    if state.phase != expected {
        return Err(ContractError::PhaseMismatch {
            expected,
            actual: state.phase.clone(),
        });
    }
    Ok(())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::RoundState {} => {
            let state = ROUND_STATE.load(deps.storage)?;
            let is_complete = state.is_complete();
            to_json_binary(&RoundStateResponse {
                round_id: state.round_id,
                operator: state.operator.to_string(),
                phase: state.phase.clone(),
                expected: state.expected,
                completed: state.completed,
                online_state: OnlineStateResponse {
                    current_deactivate_commitment: state.online.current_deactivate_commitment,
                    deactivate_batch_end_hash: state.online.deactivate_batch_end_hash,
                    latest_deactivate_root: state.online.latest_deactivate_root,
                    latest_state_root: state.online.latest_state_root,
                },
                checkpoint: state.checkpoint,
                is_complete,
                verified_proofs: state.verified_proofs,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::InitialOnlineState;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    fn verifier(fill: u8) -> VerifierConfig {
        VerifierConfig {
            base_vkey_hash: Binary::from(vec![fill; 32]),
            tree_vkey_hash: Binary::from(vec![fill; 32]),
            base_program_vkey_digest: Binary::from(vec![fill; 32]),
            tree_program_vkey_digest: Binary::from(vec![fill; 32]),
            expected_poll_id: Binary::from(vec![fill; 32]),
            expected_coord_pub_key_hash: Binary::from(vec![fill; 32]),
        }
    }

    fn instantiate_msg() -> InstantiateMsg {
        InstantiateMsg {
            round_id: Some("round-1".to_string()),
            verifier: verifier(7),
            initial_online_state: InitialOnlineState {
                current_deactivate_commitment: Binary::from(vec![1; 32]),
                deactivate_batch_start_hash: Binary::from(vec![2; 32]),
            },
        }
    }

    #[test]
    fn instantiate_opens_round_and_pins_operator() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("operator", &[]),
            instantiate_msg(),
        )
        .unwrap();
        let response = query(deps.as_ref(), mock_env(), QueryMsg::RoundState {}).unwrap();
        let state: RoundStateResponse = cosmwasm_std::from_json(response).unwrap();
        assert_eq!(state.operator, "operator");
        assert_eq!(state.phase, RoundPhase::Open);
        assert!(!state.is_complete);
    }

    #[test]
    fn close_requires_operator_and_sets_post_round_plan() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("operator", &[]),
            instantiate_msg(),
        )
        .unwrap();
        let msg = ExecuteMsg::CloseRound {
            process_messages_count: 10,
            tally_count: 11,
            initial_state_commitment: Binary::from(vec![3; 32]),
            message_batch_start_hash: Binary::from(vec![4; 32]),
            message_batch_end_hash: Binary::from(vec![5; 32]),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("other", &[]),
            msg.clone(),
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized));
        execute(deps.as_mut(), mock_env(), mock_info("operator", &[]), msg).unwrap();
        let state = ROUND_STATE.load(deps.as_ref().storage).unwrap();
        assert_eq!(state.phase, RoundPhase::Closed);
        assert_eq!(state.expected.process_messages, 10);
        assert_eq!(state.expected.tally, 11);
    }

    #[test]
    fn online_decoder_rejects_non_online_stage() {
        let mut bytes = Vec::from(PUBLIC_MAGIC);
        bytes.push(1);
        bytes.resize(8 + 1 + 9 * 32, 0);
        let err = decode_online_public_output(&bytes).unwrap_err();
        assert!(matches!(err, ContractError::InvalidPublicOutput { .. }));
    }

    #[test]
    fn invalid_base_vkey_length_is_rejected() {
        let mut deps = mock_dependencies();
        let mut msg = instantiate_msg();
        msg.verifier.base_vkey_hash = Binary::from(vec![0; 31]);
        let err =
            instantiate(deps.as_mut(), mock_env(), mock_info("operator", &[]), msg).unwrap_err();
        assert!(matches!(
            err,
            ContractError::InvalidConfigLength { actual: 31, .. }
        ));
    }

    #[test]
    fn deactivate_transition_is_checked_before_proof_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("operator", &[]),
            instantiate_msg(),
        )
        .unwrap();
        let public_values = process_deactivate_public_values(9, 2, 7, 7);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("operator", &[]),
            ExecuteMsg::VerifyOnlineProof {
                stage: RoundStage::ProcessDeactivate,
                proof: Binary::default(),
                public_values,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ContractError::DeactivateTransitionMismatch { field }
                if field == "current_deactivate_commitment"
        ));
    }

    #[test]
    fn add_new_key_requires_a_verified_deactivate_root() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("operator", &[]),
            instantiate_msg(),
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &[]),
            ExecuteMsg::VerifyOnlineProof {
                stage: RoundStage::AddNewKey,
                proof: Binary::default(),
                public_values: add_new_key_public_values(9, 8, 7),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::UnknownDeactivateRoot));
    }

    #[test]
    fn finalization_checkpoint_is_checked_before_proof_verification() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("operator", &[]),
            instantiate_msg(),
        )
        .unwrap();
        ROUND_STATE
            .update(deps.as_mut().storage, |mut state| -> StdResult<_> {
                state.completed.process_deactivate = 1;
                state.completed.add_new_key = 1;
                state.expected.process_deactivate = 1;
                state.expected.add_new_key = 1;
                state.expected.process_messages = 10;
                state.expected.tally = 11;
                state.phase = RoundPhase::Closed;
                state.checkpoint = Some(RoundCheckpoint {
                    initial_state_commitment: Binary::from(vec![3; 32]),
                    message_batch_start_hash: Binary::from(vec![4; 32]),
                    message_batch_end_hash: Binary::from(vec![5; 32]),
                    deactivate_commitment: Binary::from(vec![1; 32]),
                });
                Ok(state)
            })
            .unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &[]),
            ExecuteMsg::VerifyCompressedFinalizationRoot {
                proof: Binary::default(),
                public_values: finalization_public_values(9),
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ContractError::FinalizationCheckpointMismatch { field }
                if field == "initial_state_commitment"
        ));
    }

    fn process_deactivate_public_values(
        current_commitment: u8,
        batch_start: u8,
        coord: u8,
        poll: u8,
    ) -> Binary {
        let mut out = Vec::from(PUBLIC_MAGIC);
        out.push(TAG_PROCESS_DEACTIVATE);
        for fill in [
            0,
            6,
            coord,
            batch_start,
            10,
            current_commitment,
            11,
            12,
            poll,
        ] {
            out.extend_from_slice(&[fill; 32]);
        }
        Binary::from(out)
    }

    fn add_new_key_public_values(root: u8, nullifier: u8, identity: u8) -> Binary {
        let mut out = Vec::from(PUBLIC_MAGIC);
        out.push(TAG_ADD_NEW_KEY);
        for fill in [0, root, identity, nullifier, 0, 0, 0, 0, 0, identity] {
            out.extend_from_slice(&[fill; 32]);
        }
        Binary::from(out)
    }

    fn finalization_public_values(initial_state: u8) -> Binary {
        let mut out = Vec::from(TREE_MAGIC);
        out.push(TAG_FINALIZATION_ROOT);
        for value in [2u32, 21, 10, 11, 2, 2] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for fill in [7, 7, 7, 7, 4, 5, initial_state, 0, 1, 0, 0, 0, 0, 0] {
            out.extend_from_slice(&[fill; 32]);
        }
        assert_eq!(out.len(), FINALIZATION_ROOT_PUBLIC_LEN);
        Binary::from(out)
    }
}
