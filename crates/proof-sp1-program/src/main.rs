#![no_main]

use amaci_proof_core::{codec::decode_input, execute_proof_logic};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();
    let input = decode_input(&input_bytes).expect("AMACI input decode failed");
    let output = execute_proof_logic(&input).expect("AMACI proof logic failed");
    sp1_zkvm::io::commit(&output);
}
