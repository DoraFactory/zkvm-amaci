use std::collections::HashMap;

use risc0_build::GuestOptionsBuilder;

fn main() {
    let mut guest_options = HashMap::new();
    guest_options.insert(
        "amaci-proof-risc0-guest",
        GuestOptionsBuilder::default()
            .features(vec!["risc0".to_string()])
            .build()
            .expect("build RISC Zero guest options"),
    );
    risc0_build::embed_methods_with_options(guest_options);
}
