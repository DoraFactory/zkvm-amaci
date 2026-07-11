use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {
    pub round_id: Option<String>,
    pub verifier: VerifierConfig,
    pub initial_online_state: InitialOnlineState,
}

#[cw_serde]
pub struct VerifierConfig {
    pub base_vkey_hash: Binary,
    pub tree_vkey_hash: Binary,
    pub base_program_vkey_digest: Binary,
    pub tree_program_vkey_digest: Binary,
    pub expected_poll_id: Binary,
    pub expected_coord_pub_key_hash: Binary,
}

#[cw_serde]
pub struct InitialOnlineState {
    pub current_deactivate_commitment: Binary,
    pub deactivate_batch_start_hash: Binary,
}

#[cw_serde]
pub struct RoundCheckpoint {
    pub initial_state_commitment: Binary,
    pub message_batch_start_hash: Binary,
    pub message_batch_end_hash: Binary,
    pub deactivate_commitment: Binary,
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
    VerifyOnlineProof {
        stage: RoundStage,
        proof: Binary,
        public_values: Binary,
    },
    CloseRound {
        process_messages_count: u32,
        tally_count: u32,
        initial_state_commitment: Binary,
        message_batch_start_hash: Binary,
        message_batch_end_hash: Binary,
    },
    VerifyCompressedFinalizationRoot {
        proof: Binary,
        public_values: Binary,
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
pub enum RoundPhase {
    Open,
    Closed,
    Finalized,
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
    pub operator: String,
    pub phase: RoundPhase,
    pub expected: RoundPlan,
    pub completed: RoundPlan,
    pub online_state: OnlineStateResponse,
    pub checkpoint: Option<RoundCheckpoint>,
    pub is_complete: bool,
    pub verified_proofs: u32,
}

#[cw_serde]
pub struct OnlineStateResponse {
    pub current_deactivate_commitment: Binary,
    pub deactivate_batch_end_hash: Binary,
    pub latest_deactivate_root: Option<Binary>,
    pub latest_state_root: Option<Binary>,
}
