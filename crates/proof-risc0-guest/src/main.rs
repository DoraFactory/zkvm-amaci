use amaci_proof_core::{
    codec::{decode_input, encode_public_output},
    execute_proof_logic,
};
use risc0_zkvm::guest::env;

fn main() {
    let len: u32 = env::read();
    let mut input_bytes = vec![0u8; len as usize];
    env::read_slice(&mut input_bytes);
    let input = decode_input(&input_bytes).expect("AMACI input decode failed");
    let output = execute_proof_logic(&input).expect("AMACI proof logic failed");
    let output_bytes = encode_public_output(&output);
    env::commit_slice(&output_bytes);
}
