use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;
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
        ExecuteMsg::VerifyCompressed {
            proof,
            public_values,
            vkey_hash,
        } => execute_verify_compressed(proof, public_values, vkey_hash),
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

fn execute_verify_compressed(
    proof: Binary,
    public_values: Binary,
    vkey_hash: Binary,
) -> Result<Response, ContractError> {
    verify_sp1_compressed(&proof, &public_values, &vkey_hash)?;
    Ok(Response::new()
        .add_attribute("method", "verify_compressed")
        .add_attribute("backend", "sp1")
        .add_attribute("proof_mode", "compressed"))
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

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifierInfo {} => to_json_binary(&VerifierInfoResponse {
            backend: "sp1".to_string(),
            proof_mode: "groth16,compressed".to_string(),
            sp1_verifier_crate: "6.3.0".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use std::path::{Path, PathBuf};

    #[test]
    fn empty_proof_is_rejected() {
        let err = verify_sp1_groth16(&[], &[], "0x00").unwrap_err();
        assert!(matches!(err, ContractError::Groth16Verification { .. }));
    }

    #[test]
    fn empty_compressed_proof_is_rejected() {
        let err = verify_sp1_compressed(&[], &[], &[]).unwrap_err();
        assert!(matches!(err, ContractError::CompressedVerification { .. }));
    }

    #[test]
    fn instantiate_and_query_report_compressed_support() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("sender", &[]);

        let response = instantiate(deps.as_mut(), env.clone(), info, InstantiateMsg {}).unwrap();
        assert_eq!(response.attributes[0].key, "method");
        assert_eq!(response.attributes[0].value, "instantiate");

        let response = query(deps.as_ref(), env, QueryMsg::VerifierInfo {}).unwrap();
        let info: VerifierInfoResponse = cosmwasm_std::from_json(response).unwrap();
        assert_eq!(info.backend, "sp1");
        assert!(info.proof_mode.contains("compressed"));
    }

    #[test]
    fn execute_compressed_rejects_empty_proof() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("sender", &[]);

        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::VerifyCompressed {
                proof: Binary::default(),
                public_values: Binary::default(),
                vkey_hash: Binary::default(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, ContractError::CompressedVerification { .. }));
    }

    #[test]
    fn compressed_fixture_verifies_when_artifacts_exist() {
        let Some(paths) = compressed_fixture_paths() else {
            eprintln!("skipping compressed fixture test: artifacts not found");
            return;
        };

        let proof = std::fs::read(&paths.proof).unwrap();
        let public_values = std::fs::read(&paths.public_values).unwrap();
        let vkey_hash = std::fs::read(&paths.vkey_hash).unwrap();

        verify_sp1_compressed(&proof, &public_values, &vkey_hash).unwrap();

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("sender", &[]);
        let response = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::VerifyCompressed {
                proof: proof.into(),
                public_values: public_values.into(),
                vkey_hash: vkey_hash.into(),
            },
        )
        .unwrap();

        assert!(response
            .attributes
            .iter()
            .any(|attr| attr.key == "proof_mode" && attr.value == "compressed"));
    }

    struct CompressedFixturePaths {
        proof: PathBuf,
        public_values: PathBuf,
        vkey_hash: PathBuf,
    }

    fn compressed_fixture_paths() -> Option<CompressedFixturePaths> {
        let circuit = std::env::var("AMACI_COMPRESSED_FIXTURE")
            .unwrap_or_else(|_| "process-messages-native-2-1-5-full".to_string());
        let base = Path::new("sp1-proofs");
        let paths = CompressedFixturePaths {
            proof: base.join(format!("{circuit}.sp1-compressed-proof.bytes")),
            public_values: base.join(format!("{circuit}.sp1-compressed.public.bin")),
            vkey_hash: base.join(format!("{circuit}.sp1-compressed.vkey.bin")),
        };

        if paths.proof.exists() && paths.public_values.exists() && paths.vkey_hash.exists() {
            Some(paths)
        } else {
            None
        }
    }
}
