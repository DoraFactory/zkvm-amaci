use cosmwasm_schema::cw_serde;
use cw_storage_plus::Item;

use crate::msg::{RoundPlan, RoundStage};

pub const ROUND_STATE: Item<StoredRoundState> = Item::new("round_state");

#[cw_serde]
pub struct StoredRoundState {
    pub round_id: String,
    pub expected: RoundPlan,
    pub completed: RoundPlan,
    pub verified_proofs: u32,
}

impl StoredRoundState {
    pub fn next_stage(&self) -> Option<RoundStage> {
        if self.completed.process_deactivate < self.expected.process_deactivate {
            Some(RoundStage::ProcessDeactivate)
        } else if self.completed.add_new_key < self.expected.add_new_key {
            Some(RoundStage::AddNewKey)
        } else if self.completed.process_messages < self.expected.process_messages {
            Some(RoundStage::ProcessMessages)
        } else if self.completed.tally < self.expected.tally {
            Some(RoundStage::Tally)
        } else {
            None
        }
    }

    pub fn is_complete(&self) -> bool {
        self.next_stage().is_none()
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

pub fn plan_total(plan: &RoundPlan) -> u32 {
    plan.process_deactivate
        .saturating_add(plan.add_new_key)
        .saturating_add(plan.process_messages)
        .saturating_add(plan.tally)
}
