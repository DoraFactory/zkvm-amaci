use crate::circuits::{add_new_key, process_deactivate, process_messages, tally_votes};
use crate::error::ProofResult;
use crate::public_output::PublicOutput;
use crate::types::ProverInput;

pub fn execute_proof_logic(input: &ProverInput) -> ProofResult<PublicOutput> {
    match input {
        ProverInput::ProcessMessages(input) => {
            process_messages::execute(input).map(PublicOutput::ProcessMessages)
        }
        ProverInput::TallyVotes(input) => tally_votes::execute(input).map(PublicOutput::TallyVotes),
        ProverInput::ProcessDeactivate(input) => {
            process_deactivate::execute(input).map(PublicOutput::ProcessDeactivate)
        }
        ProverInput::AddNewKey(input) => add_new_key::execute(input).map(PublicOutput::AddNewKey),
    }
}
