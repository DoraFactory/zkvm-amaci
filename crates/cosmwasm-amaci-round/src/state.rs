use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary};
use cw_storage_plus::{Item, Map};

use crate::msg::{RoundCheckpoint, RoundPhase, RoundPlan, VerifierConfig};

pub const ROUND_STATE: Item<StoredRoundState> = Item::new("round_state_v2");
pub const VERIFIED_DEACTIVATE_ROOTS: Map<&[u8], bool> = Map::new("verified_deactivate_roots");
pub const USED_NULLIFIERS: Map<&[u8], bool> = Map::new("used_add_key_nullifiers");

#[cw_serde]
pub struct OnlineState {
    pub current_deactivate_commitment: Binary,
    pub deactivate_batch_end_hash: Binary,
    pub latest_deactivate_root: Option<Binary>,
    pub latest_state_root: Option<Binary>,
}

#[cw_serde]
pub struct StoredRoundState {
    pub round_id: String,
    pub operator: Addr,
    pub phase: RoundPhase,
    pub expected: RoundPlan,
    pub completed: RoundPlan,
    pub verified_proofs: u32,
    pub verifier: VerifierConfig,
    pub online: OnlineState,
    pub checkpoint: Option<RoundCheckpoint>,
}

impl StoredRoundState {
    pub fn is_complete(&self) -> bool {
        self.phase == RoundPhase::Finalized
    }
}

pub fn empty_completed_plan() -> RoundPlan {
    RoundPlan {
        process_deactivate: 0,
        add_new_key: 0,
        process_messages: 0,
        tally: 0,
    }
}
