use amaci_proof_core::sample_inputs;
use amaci_proof_core::{execute_proof_logic, ProverInput, PublicOutput};
use std::env;
use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse()?;

    let build_start = Instant::now();
    let input = sample_inputs::built_in_input(&config.circuit)?.ok_or_else(|| {
        format!(
            "unsupported circuit {}; supported: {}",
            config.circuit,
            sample_inputs::supported_inputs()
        )
    })?;
    let build_elapsed = build_start.elapsed();

    let mut total = Duration::ZERO;
    let mut last_output = None;
    for _ in 0..config.iters {
        let start = Instant::now();
        let output = execute_proof_logic(black_box(&input))?;
        total += start.elapsed();
        last_output = Some(output);
    }

    let output = last_output.expect("iters is validated to be non-zero");
    println!("circuit={}", config.circuit);
    println!("iters={}", config.iters);
    println!("input_build_ms={:.3}", millis(build_elapsed));
    println!("total_execute_ms={:.3}", millis(total));
    println!("avg_execute_ms={:.3}", millis(total) / config.iters as f64);
    println!("output={}", output_name(&output));
    println!("input_hash={}", input_hash(&input));
    Ok(())
}

struct Config {
    circuit: String,
    iters: usize,
}

impl Config {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut circuit = "process-messages-native-1-1".to_string();
        let mut iters = 20usize;
        let mut args = env::args().skip(1).peekable();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--iters" => {
                    let value = args
                        .next()
                        .ok_or("missing value after --iters")?
                        .parse::<usize>()?;
                    if value == 0 {
                        return Err("--iters must be greater than zero".into());
                    }
                    iters = value;
                }
                "--help" | "-h" => return Err(usage().into()),
                other if other.starts_with("--") => {
                    return Err(format!("unknown argument: {other}\n\n{}", usage()).into());
                }
                other => circuit = other.to_string(),
            }
        }

        Ok(Self { circuit, iters })
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn output_name(output: &PublicOutput) -> &'static str {
    match output {
        PublicOutput::ProcessMessages(_) => "ProcessMessages",
        PublicOutput::TallyVotes(_) => "TallyVotes",
        PublicOutput::ProcessDeactivate(_) => "ProcessDeactivate",
        PublicOutput::AddNewKey(_) => "AddNewKey",
    }
}

fn input_hash(input: &ProverInput) -> &amaci_proof_core::Field {
    match input {
        ProverInput::ProcessMessages(input) => &input.input_hash,
        ProverInput::TallyVotes(input) => &input.input_hash,
        ProverInput::ProcessDeactivate(input) => &input.input_hash,
        ProverInput::AddNewKey(input) => &input.input_hash,
    }
}

fn usage() -> &'static str {
    "usage:\n  cargo run --release -p amaci-proof-core --features zkvm-native-crypto --bin native_profile -- [circuit] [--iters N]"
}
