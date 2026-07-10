#![no_main]

use amaci_proof_core::tree_aggregate::{
    build_tree_request_output, encode_tree_public_output, TreeAggregateRequest,
};
use sha2::{Digest as Sha2Digest, Sha256};
use sp1_zkvm::lib::verify::verify_sp1_proof;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let request: TreeAggregateRequest = sp1_zkvm::io::read();
    assert_eq!(
        request.child_vkey_digests.len(),
        request.child_public_outputs.len(),
        "tree child proof metadata length mismatch"
    );
    for (vkey_digest, public_output) in request
        .child_vkey_digests
        .iter()
        .zip(&request.child_public_outputs)
    {
        let public_values_digest: [u8; 32] = Sha256::digest(public_output).into();
        verify_sp1_proof(vkey_digest, &public_values_digest);
    }
    let output = build_tree_request_output(&request).expect("invalid tree aggregate request");
    sp1_zkvm::io::commit_slice(&encode_tree_public_output(&output));
}
