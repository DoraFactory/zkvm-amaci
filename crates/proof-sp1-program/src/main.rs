#![no_main]

use amaci_proof_core::{execute_proof_logic, ProverInput};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read::<ProverInput>();
    let output = execute_proof_logic(&input).expect("AMACI proof logic failed");
    sp1_zkvm::io::commit(&output);
}
