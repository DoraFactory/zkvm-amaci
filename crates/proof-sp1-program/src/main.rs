#[cfg(feature = "sp1")]
fn main() {
    use amaci_proof_core::{execute_proof_logic, ProverInput};

    let input = sp1_zkvm::io::read::<ProverInput>();
    let output = execute_proof_logic(&input).expect("AMACI proof logic failed");
    sp1_zkvm::io::commit(&output);
}

#[cfg(not(feature = "sp1"))]
fn main() {
    // Default build stays dependency-light so `proof-core` can be checked and
    // tested before selecting an SP1 SDK version.
}
