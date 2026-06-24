use amaci_proof_core::sample_inputs;
use amaci_proof_core::{execute_proof_logic, ProverInput, PublicOutput};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::ProvingKey;
use sp1_sdk::{include_elf, HashableKey, SP1ProofWithPublicValues, SP1PublicValues};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const AMACI_SP1_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-program");

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args)? {
        Command::Prove {
            circuit,
            proof_path,
            public_path,
        } => prove(&circuit, proof_path.as_deref(), public_path.as_deref())?,
        Command::Verify {
            proof_path,
            public_path,
        } => verify(&proof_path, public_path.as_deref())?,
        Command::Execute {
            circuit,
            public_path,
        } => execute(&circuit, public_path.as_deref())?,
    }

    Ok(())
}

enum Command {
    Prove {
        circuit: String,
        proof_path: Option<PathBuf>,
        public_path: Option<PathBuf>,
    },
    Verify {
        proof_path: PathBuf,
        public_path: Option<PathBuf>,
    },
    Execute {
        circuit: String,
        public_path: Option<PathBuf>,
    },
}

fn parse_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    if args.first().map(String::as_str) == Some("verify") {
        parse_verify_command(&args[1..])
    } else if args.first().map(String::as_str) == Some("execute") {
        parse_execute_command(&args[1..])
    } else if args.first().map(String::as_str) == Some("prove") {
        parse_prove_command(&args[1..])
    } else {
        let circuit = args
            .first()
            .cloned()
            .unwrap_or_else(|| "process-messages-2-1-5".to_string());
        Ok(Command::Prove {
            circuit,
            proof_path: None,
            public_path: None,
        })
    }
}

fn parse_prove_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = "process-messages-2-1-5".to_string();
    let mut proof_path = None;
    let mut public_path = None;
    let mut i = 0;

    if args.first().is_some_and(|arg| !arg.starts_with("--")) {
        circuit = args[0].clone();
        i = 1;
    }

    while i < args.len() {
        match args[i].as_str() {
            "--proof" => {
                i += 1;
                proof_path = Some(next_path(args, i, "--proof")?);
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
        proof_path,
        public_path,
    })
}

fn parse_verify_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut proof_path = None;
    let mut public_path = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--proof" => {
                i += 1;
                proof_path = Some(next_path(args, i, "--proof")?);
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
        proof_path: proof_path
            .ok_or_else(|| format!("missing required --proof PATH for verify\n\n{}", usage()))?,
        public_path,
    })
}

fn parse_execute_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = "process-messages-2-1-5".to_string();
    let mut public_path = None;
    let mut i = 0;

    if args.first().is_some_and(|arg| !arg.starts_with("--")) {
        circuit = args[0].clone();
        i = 1;
    }

    while i < args.len() {
        match args[i].as_str() {
            "--public" => {
                i += 1;
                public_path = Some(next_path(args, i, "--public")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => {
                return Err(format!("unknown execute argument: {other}\n\n{}", usage()).into());
            }
        }
        i += 1;
    }

    Ok(Command::Execute {
        circuit,
        public_path,
    })
}

fn next_path(args: &[String], index: usize, flag: &str) -> Result<PathBuf, Box<dyn Error>> {
    args.get(index)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing path after {flag}").into())
}

fn usage() -> &'static str {
    "usage:\n  amaci-proof-sp1-host [circuit]\n  amaci-proof-sp1-host execute [circuit] [--public PATH]\n  amaci-proof-sp1-host prove [circuit] [--proof PATH] [--public PATH]\n  amaci-proof-sp1-host verify --proof PATH [--public PATH]"
}

fn prove(
    circuit: &str,
    proof_path: Option<&Path>,
    public_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let input = built_in_input(circuit)?;
    let expected_output = execute_proof_logic(&input)?;

    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(AMACI_SP1_ELF)?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    let proof = client.prove(&pk, stdin).core().run()?;
    client.verify(&proof, pk.verifying_key(), None)?;
    let journal_output = decode_public_output(&proof)?;
    if journal_output != expected_output {
        return Err("public values did not match native proof-core output".into());
    }

    println!("circuit={circuit}");
    println!("vkey_hash={}", pk.verifying_key().bytes32());
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = proof_path {
        write_parented_proof(path, &proof)?;
        println!("proof={}", path.display());
    }

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn execute(circuit: &str, public_path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let input = built_in_input(circuit)?;
    let expected_output = execute_proof_logic(&input)?;

    let client = ProverClient::builder().cpu().build();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    let (public_values, report) = client.execute(AMACI_SP1_ELF, stdin).run()?;
    let journal_output = decode_public_values(public_values);
    if journal_output != expected_output {
        return Err("execute public values did not match native proof-core output".into());
    }

    println!("circuit={circuit}");
    println!("execute ok");
    println!("instructions={}", report.total_instruction_count());
    println!("syscalls={}", report.total_syscall_count());
    println!(
        "touched_memory_addresses={}",
        report.touched_memory_addresses
    );
    if let Some(gas) = report.gas() {
        println!("gas={gas}");
    }
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn verify(proof_path: &Path, public_path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let proof = SP1ProofWithPublicValues::load(proof_path)?;
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(AMACI_SP1_ELF)?;
    client.verify(&proof, pk.verifying_key(), None)?;
    let journal_output = decode_public_output(&proof)?;

    println!("proof verify ok");
    println!("proof={}", proof_path.display());
    println!("vkey_hash={}", pk.verifying_key().bytes32());
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn decode_public_output(proof: &SP1ProofWithPublicValues) -> Result<PublicOutput, Box<dyn Error>> {
    Ok(decode_public_values(proof.public_values.clone()))
}

fn decode_public_values(mut public_values: SP1PublicValues) -> PublicOutput {
    public_values.read::<PublicOutput>()
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

fn write_parented_proof(
    path: &Path,
    proof: &SP1ProofWithPublicValues,
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    proof.save(path)?;
    Ok(())
}

fn built_in_input(circuit: &str) -> Result<ProverInput, Box<dyn Error>> {
    sample_inputs::built_in_input(circuit)?.ok_or_else(|| {
        format!(
            "unsupported circuit {circuit}; supported: {}",
            sample_inputs::supported_inputs()
        )
        .into()
    })
}
