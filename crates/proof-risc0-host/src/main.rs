use amaci_proof_core::{
    codec::{decode_public_output, encode_input},
    sample_inputs,
};
use amaci_proof_core::{execute_proof_logic, PublicOutput};
use amaci_proof_risc0_methods::{AMACI_PROOF_RISC0_GUEST_ELF, AMACI_PROOF_RISC0_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CIRCUIT: &str = "process-messages-native-2-1-5-full";

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args)? {
        Command::Prove {
            circuit,
            receipt_path,
            public_path,
        } => prove(&circuit, receipt_path.as_deref(), public_path.as_deref())?,
        Command::Verify {
            receipt_path,
            public_path,
        } => verify(&receipt_path, public_path.as_deref())?,
    }

    Ok(())
}

enum Command {
    Prove {
        circuit: String,
        receipt_path: Option<PathBuf>,
        public_path: Option<PathBuf>,
    },
    Verify {
        receipt_path: PathBuf,
        public_path: Option<PathBuf>,
    },
}

fn parse_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    if args.first().map(String::as_str) == Some("verify") {
        parse_verify_command(&args[1..])
    } else if args.first().map(String::as_str) == Some("prove") {
        parse_prove_command(&args[1..])
    } else {
        let circuit = args
            .first()
            .cloned()
            .unwrap_or_else(|| DEFAULT_CIRCUIT.to_string());
        Ok(Command::Prove {
            circuit,
            receipt_path: None,
            public_path: None,
        })
    }
}

fn parse_prove_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = DEFAULT_CIRCUIT.to_string();
    let mut receipt_path = None;
    let mut public_path = None;
    let mut i = 0;

    if args.first().is_some_and(|arg| !arg.starts_with("--")) {
        circuit = args[0].clone();
        i = 1;
    }

    while i < args.len() {
        match args[i].as_str() {
            "--receipt" => {
                i += 1;
                receipt_path = Some(next_path(args, i, "--receipt")?);
            }
            "--public" => {
                i += 1;
                public_path = Some(next_path(args, i, "--public")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => return Err(format!("unknown prove argument: {other}\n\n{}", usage()).into()),
        }
        i += 1;
    }

    Ok(Command::Prove {
        circuit,
        receipt_path,
        public_path,
    })
}

fn parse_verify_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut receipt_path = None;
    let mut public_path = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--receipt" => {
                i += 1;
                receipt_path = Some(next_path(args, i, "--receipt")?);
            }
            "--public" => {
                i += 1;
                public_path = Some(next_path(args, i, "--public")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => return Err(format!("unknown verify argument: {other}\n\n{}", usage()).into()),
        }
        i += 1;
    }

    Ok(Command::Verify {
        receipt_path: receipt_path
            .ok_or_else(|| format!("missing required --receipt PATH for verify\n\n{}", usage()))?,
        public_path,
    })
}

fn next_path(args: &[String], index: usize, flag: &str) -> Result<PathBuf, Box<dyn Error>> {
    args.get(index)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing path after {flag}").into())
}

fn usage() -> &'static str {
    "usage:\n  amaci-proof-risc0-host [circuit]\n  amaci-proof-risc0-host prove [circuit] [--receipt PATH] [--public PATH]\n  amaci-proof-risc0-host verify --receipt PATH [--public PATH]"
}

fn prove(
    circuit: &str,
    receipt_path: Option<&Path>,
    public_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let input = sample_inputs::built_in_input(circuit)?.ok_or_else(|| {
        format!(
            "unsupported circuit {circuit}; supported: {}",
            sample_inputs::supported_inputs()
        )
    })?;

    let expected_output = execute_proof_logic(&input)?;
    let input_bytes = encode_input(&input);
    let input_len = input_bytes.len() as u32;
    println!("input_bytes={}", input_bytes.len());
    let env = ExecutorEnv::builder()
        .write(&input_len)?
        .write_slice(&input_bytes)
        .build()?;
    let prove_info = default_prover().prove(env, AMACI_PROOF_RISC0_GUEST_ELF)?;
    let receipt = prove_info.receipt;
    receipt.verify(AMACI_PROOF_RISC0_GUEST_ID)?;
    println!("public_bytes={}", receipt.journal.bytes.len());
    let journal_output: PublicOutput = decode_public_output(&receipt.journal.bytes)?;
    if journal_output != expected_output {
        return Err("journal output did not match native proof-core output".into());
    }

    println!("circuit={circuit}");
    println!("image_id={:?}", AMACI_PROOF_RISC0_GUEST_ID);
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = receipt_path {
        write_parented(path, &bincode::serialize(&receipt)?)?;
        println!("receipt={}", path.display());
    }

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn verify(receipt_path: &Path, public_path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(receipt_path)?;
    let receipt: Receipt = bincode::deserialize(&bytes)?;
    receipt.verify(AMACI_PROOF_RISC0_GUEST_ID)?;
    println!("public_bytes={}", receipt.journal.bytes.len());
    let journal_output: PublicOutput = decode_public_output(&receipt.journal.bytes)?;

    println!("receipt verify ok");
    println!("receipt={}", receipt_path.display());
    println!("image_id={:?}", AMACI_PROOF_RISC0_GUEST_ID);
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn write_parented(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}
