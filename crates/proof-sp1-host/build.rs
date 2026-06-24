fn main() {
    let args = sp1_build::BuildArgs::default();
    sp1_build::build_program_with_args("../proof-sp1-program", args);
}
