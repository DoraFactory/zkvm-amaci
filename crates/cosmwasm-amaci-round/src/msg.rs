use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {
    pub round_id: Option<String>,
    pub expected: RoundPlan,
}

#[cw_serde]
pub struct RoundPlan {
    pub process_deactivate: u32,
    pub add_new_key: u32,
    pub process_messages: u32,
    pub tally: u32,
}

#[cw_serde]
pub enum ExecuteMsg {
    VerifyCompressedStage {
        stage: RoundStage,
        proof: Binary,
        public_values: Binary,
        vkey_hash: Binary,
    },
}

#[cw_serde]
pub enum RoundStage {
    ProcessDeactivate,
    AddNewKey,
    ProcessMessages,
    Tally,
}

impl RoundStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoundStage::ProcessDeactivate => "process_deactivate",
            RoundStage::AddNewKey => "add_new_key",
            RoundStage::ProcessMessages => "process_messages",
            RoundStage::Tally => "tally",
        }
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(RoundStateResponse)]
    RoundState {},
}

#[cw_serde]
pub struct RoundStateResponse {
    pub round_id: String,
    pub expected: RoundPlan,
    pub completed: RoundPlan,
    pub next_stage: Option<RoundStage>,
    pub is_complete: bool,
    pub verified_proofs: u32,
}
