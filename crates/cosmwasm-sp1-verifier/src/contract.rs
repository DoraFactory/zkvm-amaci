use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, VerifierInfoResponse};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyGroth16 {
            proof,
            public_values,
            vkey_hash,
        } => execute_verify_groth16(proof, public_values, vkey_hash),
    }
}

fn execute_verify_groth16(
    proof: Binary,
    public_values: Binary,
    vkey_hash: String,
) -> Result<Response, ContractError> {
    verify_sp1_groth16(&proof, &public_values, &vkey_hash)?;
    Ok(Response::new()
        .add_attribute("method", "verify_groth16")
        .add_attribute("backend", "sp1")
        .add_attribute("proof_mode", "groth16"))
}

pub fn verify_sp1_groth16(
    proof: &[u8],
    public_values: &[u8],
    vkey_hash: &str,
) -> Result<(), ContractError> {
    Groth16Verifier::verify(proof, public_values, vkey_hash, *GROTH16_VK_BYTES).map_err(|err| {
        ContractError::Groth16Verification {
            reason: err.to_string(),
        }
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifierInfo {} => to_json_binary(&VerifierInfoResponse {
            backend: "sp1".to_string(),
            proof_mode: "groth16".to_string(),
            sp1_verifier_crate: "6.3.0".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_proof_is_rejected() {
        let err = verify_sp1_groth16(&[], &[], "0x00").unwrap_err();
        assert!(matches!(err, ContractError::Groth16Verification { .. }));
    }
}
