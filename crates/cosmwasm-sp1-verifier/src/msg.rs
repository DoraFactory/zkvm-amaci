use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    VerifyGroth16 {
        proof: Binary,
        public_values: Binary,
        vkey_hash: String,
    },
    VerifyCompressed {
        proof: Binary,
        public_values: Binary,
        vkey_hash: Binary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(VerifierInfoResponse)]
    VerifierInfo {},
}

#[cw_serde]
pub struct VerifierInfoResponse {
    pub backend: String,
    pub proof_mode: String,
    pub sp1_verifier_crate: String,
}
