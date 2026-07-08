#![no_main]

use amaci_proof_core::aggregate::{
    build_process_messages_aggregate_public_output, build_tally_aggregate_public_output,
    encode_aggregate_public_output, AggregatePublicOutput,
};
use sha2::{Digest as Sha2Digest, Sha256};
use sp1_zkvm::lib::verify::verify_sp1_proof;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let aggregate_kind: u8 = sp1_zkvm::io::read();
    let child_vkey_digest: [u32; 8] = sp1_zkvm::io::read();
    let child_public_outputs: Vec<Vec<u8>> = sp1_zkvm::io::read();

    for public_output in &child_public_outputs {
        let public_values_digest: [u8; 32] = Sha256::digest(public_output).into();
        verify_sp1_proof(&child_vkey_digest, &public_values_digest);
    }

    let output = match aggregate_kind {
        1 => AggregatePublicOutput::ProcessMessages(
            build_process_messages_aggregate_public_output(&child_public_outputs)
                .expect("invalid process messages aggregate child public outputs"),
        ),
        2 => AggregatePublicOutput::Tally(
            build_tally_aggregate_public_output(&child_public_outputs)
                .expect("invalid tally aggregate child public outputs"),
        ),
        _ => panic!("unknown aggregate kind"),
    };
    let output_bytes = encode_aggregate_public_output(&output);
    sp1_zkvm::io::commit_slice(&output_bytes);
}
