use std::collections::HashMap;

use risc0_build::GuestOptionsBuilder;

fn main() {
    let mut guest_features = vec!["risc0".to_string()];
    if std::env::var_os("CARGO_FEATURE_ZKVM_NATIVE_CRYPTO").is_some() {
        guest_features.push("zkvm-native-crypto".to_string());
    }

    let mut guest_options = HashMap::new();
    guest_options.insert(
        "amaci-proof-risc0-guest",
        GuestOptionsBuilder::default()
            .features(guest_features)
            .build()
            .expect("build RISC Zero guest options"),
    );
    risc0_build::embed_methods_with_options(guest_options);
}
