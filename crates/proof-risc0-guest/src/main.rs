use amaci_proof_core::{execute_proof_logic, ProverInput};
use risc0_zkvm::guest::env;

fn main() {
    let input: ProverInput = env::read();
    let output = execute_proof_logic(&input).expect("AMACI proof logic failed");
    env::commit(&output);
}
