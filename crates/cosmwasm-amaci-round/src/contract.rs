use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, RoundStage, RoundStateResponse};
use crate::state::{empty_completed_plan, plan_total, StoredRoundState, ROUND_STATE};

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

    let round_id = msg
        .round_id
        .unwrap_or_else(|| "zkvm-amaci-round-e2e".to_string());
    let state = StoredRoundState {
        round_id: round_id.clone(),
        expected: msg.expected,
        completed: empty_completed_plan(),
        verified_proofs: 0,
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
    }
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
    advance_stage(&mut state, &stage);
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

fn advance_stage(state: &mut StoredRoundState, stage: &RoundStage) {
    match stage {
        RoundStage::ProcessDeactivate => state.completed.process_deactivate += 1,
        RoundStage::AddNewKey => state.completed.add_new_key += 1,
        RoundStage::ProcessMessages => state.completed.process_messages += 1,
        RoundStage::Tally => state.completed.tally += 1,
    }
    state.verified_proofs += 1;
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
}
