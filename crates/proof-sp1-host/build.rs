fn main() {
    let mut args = sp1_build::BuildArgs::default();
    if std::env::var_os("CARGO_FEATURE_ZKVM_NATIVE_CRYPTO").is_some() {
        args.features.push("zkvm-native-crypto".to_string());
    }
    sp1_build::build_program_with_args("../proof-sp1-program", args);
}
