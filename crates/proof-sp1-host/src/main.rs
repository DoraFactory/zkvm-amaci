use amaci_proof_core::{
    codec::{decode_public_output, encode_input},
    sample_inputs,
};
use amaci_proof_core::{execute_proof_logic, ProverInput, PublicOutput};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::ProvingKey;
use sp1_sdk::{include_elf, HashableKey, SP1ProofWithPublicValues, SP1PublicValues};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const AMACI_SP1_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-program");
const DEFAULT_CIRCUIT: &str = "process-messages-native-2-1-5-full";

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
        Command::ProveGroth16 {
            circuit,
            proof_path,
            proof_bytes_path,
            public_path,
            public_bytes_path,
            vkey_path,
        } => prove_groth16(
            &circuit,
            proof_path.as_deref(),
            proof_bytes_path.as_deref(),
            public_path.as_deref(),
            public_bytes_path.as_deref(),
            vkey_path.as_deref(),
        )?,
        Command::Verify {
            proof_path,
            public_path,
        } => verify(&proof_path, public_path.as_deref())?,
        Command::VerifyGroth16 {
            proof_path,
            proof_bytes_path,
            public_bytes_path,
            vkey_hash,
            public_path,
        } => verify_groth16(
            proof_path.as_deref(),
            proof_bytes_path.as_deref(),
            public_bytes_path.as_deref(),
            vkey_hash.as_deref(),
            public_path.as_deref(),
        )?,
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
    ProveGroth16 {
        circuit: String,
        proof_path: Option<PathBuf>,
        proof_bytes_path: Option<PathBuf>,
        public_path: Option<PathBuf>,
        public_bytes_path: Option<PathBuf>,
        vkey_path: Option<PathBuf>,
    },
    Verify {
        proof_path: PathBuf,
        public_path: Option<PathBuf>,
    },
    VerifyGroth16 {
        proof_path: Option<PathBuf>,
        proof_bytes_path: Option<PathBuf>,
        public_bytes_path: Option<PathBuf>,
        vkey_hash: Option<String>,
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
    } else if args.first().map(String::as_str) == Some("verify-groth16") {
        parse_verify_groth16_command(&args[1..])
    } else if args.first().map(String::as_str) == Some("execute") {
        parse_execute_command(&args[1..])
    } else if args.first().map(String::as_str) == Some("prove-groth16") {
        parse_prove_groth16_command(&args[1..])
    } else if args.first().map(String::as_str) == Some("prove") {
        parse_prove_command(&args[1..])
    } else {
        let circuit = args
            .first()
            .cloned()
            .unwrap_or_else(|| DEFAULT_CIRCUIT.to_string());
        Ok(Command::Prove {
            circuit,
            proof_path: None,
            public_path: None,
        })
    }
}

fn parse_prove_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = DEFAULT_CIRCUIT.to_string();
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

fn parse_prove_groth16_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = DEFAULT_CIRCUIT.to_string();
    let mut proof_path = None;
    let mut proof_bytes_path = None;
    let mut public_path = None;
    let mut public_bytes_path = None;
    let mut vkey_path = None;
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
            "--proof-bytes" => {
                i += 1;
                proof_bytes_path = Some(next_path(args, i, "--proof-bytes")?);
            }
            "--public" => {
                i += 1;
                public_path = Some(next_path(args, i, "--public")?);
            }
            "--public-bytes" => {
                i += 1;
                public_bytes_path = Some(next_path(args, i, "--public-bytes")?);
            }
            "--vkey" => {
                i += 1;
                vkey_path = Some(next_path(args, i, "--vkey")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => {
                return Err(
                    format!("unknown prove-groth16 argument: {other}\n\n{}", usage()).into(),
                );
            }
        }
        i += 1;
    }

    Ok(Command::ProveGroth16 {
        circuit,
        proof_path,
        proof_bytes_path,
        public_path,
        public_bytes_path,
        vkey_path,
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

fn parse_verify_groth16_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut proof_path = None;
    let mut proof_bytes_path = None;
    let mut public_bytes_path = None;
    let mut vkey_hash = None;
    let mut public_path = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--proof" => {
                i += 1;
                proof_path = Some(next_path(args, i, "--proof")?);
            }
            "--proof-bytes" => {
                i += 1;
                proof_bytes_path = Some(next_path(args, i, "--proof-bytes")?);
            }
            "--public-bytes" => {
                i += 1;
                public_bytes_path = Some(next_path(args, i, "--public-bytes")?);
            }
            "--vkey" => {
                i += 1;
                vkey_hash = Some(next_value(args, i, "--vkey")?);
            }
            "--public" => {
                i += 1;
                public_path = Some(next_path(args, i, "--public")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => {
                return Err(
                    format!("unknown verify-groth16 argument: {other}\n\n{}", usage()).into(),
                );
            }
        }
        i += 1;
    }

    if proof_path.is_none()
        && (proof_bytes_path.is_none() || public_bytes_path.is_none() || vkey_hash.is_none())
    {
        return Err(format!(
            "verify-groth16 requires either --proof PATH or --proof-bytes PATH --public-bytes PATH --vkey HASH\n\n{}",
            usage()
        )
        .into());
    }

    Ok(Command::VerifyGroth16 {
        proof_path,
        proof_bytes_path,
        public_bytes_path,
        vkey_hash,
        public_path,
    })
}

fn parse_execute_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = DEFAULT_CIRCUIT.to_string();
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

fn next_value(args: &[String], index: usize, flag: &str) -> Result<String, Box<dyn Error>> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing value after {flag}").into())
}

fn usage() -> &'static str {
    "usage:\n  amaci-proof-sp1-host [circuit]\n  amaci-proof-sp1-host execute [circuit] [--public PATH]\n  amaci-proof-sp1-host prove [circuit] [--proof PATH] [--public PATH]\n  amaci-proof-sp1-host prove-groth16 [circuit] [--proof PATH] [--proof-bytes PATH] [--public PATH] [--public-bytes PATH] [--vkey PATH]\n  amaci-proof-sp1-host verify --proof PATH [--public PATH]\n  amaci-proof-sp1-host verify-groth16 --proof PATH [--public PATH]\n  amaci-proof-sp1-host verify-groth16 --proof-bytes PATH --public-bytes PATH --vkey HASH [--public PATH]"
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
    let input_bytes = encode_input(&input);
    println!("input_bytes={}", input_bytes.len());
    stdin.write_vec(input_bytes);

    let proof = client.prove(&pk, stdin).core().run()?;
    client.verify(&proof, pk.verifying_key(), None)?;
    println!("public_bytes={}", proof.public_values.as_slice().len());
    let journal_output = decode_sp1_public_output(&proof)?;
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

fn prove_groth16(
    circuit: &str,
    proof_path: Option<&Path>,
    proof_bytes_path: Option<&Path>,
    public_path: Option<&Path>,
    public_bytes_path: Option<&Path>,
    vkey_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let input = built_in_input(circuit)?;
    let expected_output = execute_proof_logic(&input)?;

    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(AMACI_SP1_ELF)?;
    let mut stdin = SP1Stdin::new();
    let input_bytes = encode_input(&input);
    println!("input_bytes={}", input_bytes.len());
    stdin.write_vec(input_bytes);

    let proof = client.prove(&pk, stdin).groth16().run()?;
    client.verify(&proof, pk.verifying_key(), None)?;
    println!("public_bytes={}", proof.public_values.as_slice().len());
    let proof_bytes = proof.bytes();
    println!("groth16_proof_bytes={}", proof_bytes.len());
    let vkey_hash = pk.verifying_key().bytes32();
    verify_groth16_artifacts(&proof_bytes, proof.public_values.as_slice(), &vkey_hash)?;
    let journal_output = decode_sp1_public_output(&proof)?;
    if journal_output != expected_output {
        return Err("Groth16 public values did not match native proof-core output".into());
    }

    println!("circuit={circuit}");
    println!("vkey_hash={vkey_hash}");
    println!("groth16 verify ok");
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = proof_path {
        write_parented_proof(path, &proof)?;
        println!("proof={}", path.display());
    }

    if let Some(path) = proof_bytes_path {
        write_parented(path, &proof_bytes)?;
        println!("proof_bytes={}", path.display());
    }

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    if let Some(path) = public_bytes_path {
        write_parented(path, proof.public_values.as_slice())?;
        println!("public_bytes_path={}", path.display());
    }

    if let Some(path) = vkey_path {
        write_parented(path, format!("{vkey_hash}\n").as_bytes())?;
        println!("vkey={}", path.display());
    }

    Ok(())
}

fn execute(circuit: &str, public_path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let input = built_in_input(circuit)?;
    let expected_output = execute_proof_logic(&input)?;

    let client = ProverClient::builder().cpu().build();
    let mut stdin = SP1Stdin::new();
    let input_bytes = encode_input(&input);
    println!("input_bytes={}", input_bytes.len());
    stdin.write_vec(input_bytes);

    let (public_values, report) = client.execute(AMACI_SP1_ELF, stdin).run()?;
    println!("public_bytes={}", public_values.as_slice().len());
    let journal_output = decode_sp1_public_values(public_values)?;
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
    println!("public_bytes={}", proof.public_values.as_slice().len());
    let journal_output = decode_sp1_public_output(&proof)?;

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

fn verify_groth16(
    proof_path: Option<&Path>,
    proof_bytes_path: Option<&Path>,
    public_bytes_path: Option<&Path>,
    vkey_hash: Option<&str>,
    public_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let (proof_bytes, public_values, vkey_hash) = if let Some(path) = proof_path {
        let proof = SP1ProofWithPublicValues::load(path)?;
        let client = ProverClient::builder().cpu().build();
        let pk = client.setup(AMACI_SP1_ELF)?;
        client.verify(&proof, pk.verifying_key(), None)?;
        (
            proof.bytes(),
            proof.public_values.to_vec(),
            pk.verifying_key().bytes32(),
        )
    } else {
        let proof_bytes_path = proof_bytes_path.expect("validated proof bytes path exists");
        let public_bytes_path = public_bytes_path.expect("validated public bytes path exists");
        let vkey_hash = vkey_hash.expect("validated vkey hash exists").to_string();
        (
            fs::read(proof_bytes_path)?,
            fs::read(public_bytes_path)?,
            vkey_hash,
        )
    };

    verify_groth16_artifacts(&proof_bytes, &public_values, &vkey_hash)?;
    let journal_output = decode_public_output(&public_values)?;

    println!("groth16 proof verify ok");
    println!("vkey_hash={vkey_hash}");
    println!("groth16_proof_bytes={}", proof_bytes.len());
    println!("public_bytes={}", public_values.len());
    let public_json = serde_json::to_string_pretty(&journal_output)?;
    println!("{public_json}");

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn verify_groth16_artifacts(
    proof_bytes: &[u8],
    public_values: &[u8],
    vkey_hash: &str,
) -> Result<(), Box<dyn Error>> {
    Groth16Verifier::verify(proof_bytes, public_values, vkey_hash, *GROTH16_VK_BYTES)
        .map_err(|err| format!("SP1 Groth16 verifier failed: {err}").into())
}

fn decode_sp1_public_output(
    proof: &SP1ProofWithPublicValues,
) -> Result<PublicOutput, Box<dyn Error>> {
    decode_sp1_public_values(proof.public_values.clone())
}

fn decode_sp1_public_values(
    public_values: SP1PublicValues,
) -> Result<PublicOutput, Box<dyn Error>> {
    Ok(decode_public_output(public_values.as_slice())?)
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
