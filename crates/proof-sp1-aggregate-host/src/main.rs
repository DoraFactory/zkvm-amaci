use amaci_proof_core::aggregate::{
    build_process_messages_aggregate_public_output, build_tally_aggregate_public_output,
    decode_aggregate_public_output, AggregatePublicOutput,
};
use base64::Engine;
use sp1_core_executor::SP1CoreOpts;
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{include_elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const AMACI_SP1_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-program");
const AMACI_SP1_AGGREGATE_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-aggregate-program");
const DEFAULT_COMPRESSED_SHARD_SIZE: usize = 1 << 23;
const MAX_COMPRESSED_SHARD_SIZE: usize = 1 << 24;

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args)? {
        Command::AggregateTally {
            children,
            proof_path,
            proof_bytes_path,
            public_path,
            public_bytes_path,
            vkey_path,
        } => aggregate(
            AggregateKind::Tally,
            &children,
            proof_path.as_deref(),
            proof_bytes_path.as_deref(),
            public_path.as_deref(),
            public_bytes_path.as_deref(),
            vkey_path.as_deref(),
        )?,
        Command::AggregateProcessMessages {
            children,
            proof_path,
            proof_bytes_path,
            public_path,
            public_bytes_path,
            vkey_path,
        } => aggregate(
            AggregateKind::ProcessMessages,
            &children,
            proof_path.as_deref(),
            proof_bytes_path.as_deref(),
            public_path.as_deref(),
            public_bytes_path.as_deref(),
            vkey_path.as_deref(),
        )?,
        Command::VerifyCompressed {
            proof_path,
            proof_bytes_path,
            public_bytes_path,
            vkey_path,
            public_path,
        } => verify_compressed(
            proof_path.as_deref(),
            proof_bytes_path.as_deref(),
            public_bytes_path.as_deref(),
            vkey_path.as_deref(),
            public_path.as_deref(),
        )?,
    }

    Ok(())
}

enum Command {
    AggregateProcessMessages {
        children: Vec<ChildInput>,
        proof_path: Option<PathBuf>,
        proof_bytes_path: Option<PathBuf>,
        public_path: Option<PathBuf>,
        public_bytes_path: Option<PathBuf>,
        vkey_path: Option<PathBuf>,
    },
    AggregateTally {
        children: Vec<ChildInput>,
        proof_path: Option<PathBuf>,
        proof_bytes_path: Option<PathBuf>,
        public_path: Option<PathBuf>,
        public_bytes_path: Option<PathBuf>,
        vkey_path: Option<PathBuf>,
    },
    VerifyCompressed {
        proof_path: Option<PathBuf>,
        proof_bytes_path: Option<PathBuf>,
        public_bytes_path: Option<PathBuf>,
        vkey_path: Option<PathBuf>,
        public_path: Option<PathBuf>,
    },
}

fn parse_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("aggregate-tally") | None => {
            parse_aggregate_tally_command(args.get(1..).unwrap_or(&[]))
        }
        Some("aggregate-process-messages") => parse_aggregate_process_messages_command(&args[1..]),
        Some("verify-compressed") => parse_verify_compressed_command(&args[1..]),
        Some("--help") | Some("-h") => Err(usage().into()),
        Some(other) => Err(format!("unknown command: {other}\n\n{}", usage()).into()),
    }
}

fn parse_aggregate_process_messages_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let aggregate = parse_aggregate_command(args, || {
        vec![ChildInput::Msg(PathBuf::from(
            "sp1-proofs/five-signup-process-messages-full.verify-compressed.msg.json",
        ))]
    })?;
    Ok(Command::AggregateProcessMessages {
        children: aggregate.children,
        proof_path: aggregate.proof_path,
        proof_bytes_path: aggregate.proof_bytes_path,
        public_path: aggregate.public_path,
        public_bytes_path: aggregate.public_bytes_path,
        vkey_path: aggregate.vkey_path,
    })
}

fn parse_aggregate_tally_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let aggregate = parse_aggregate_command(args, || {
        vec![
            ChildInput::Msg(PathBuf::from(
                "sp1-proofs/five-signup-tally-0.verify-compressed.msg.json",
            )),
            ChildInput::Msg(PathBuf::from(
                "sp1-proofs/five-signup-tally-1.verify-compressed.msg.json",
            )),
        ]
    })?;
    Ok(Command::AggregateTally {
        children: aggregate.children,
        proof_path: aggregate.proof_path,
        proof_bytes_path: aggregate.proof_bytes_path,
        public_path: aggregate.public_path,
        public_bytes_path: aggregate.public_bytes_path,
        vkey_path: aggregate.vkey_path,
    })
}

struct AggregateCommandParts {
    children: Vec<ChildInput>,
    proof_path: Option<PathBuf>,
    proof_bytes_path: Option<PathBuf>,
    public_path: Option<PathBuf>,
    public_bytes_path: Option<PathBuf>,
    vkey_path: Option<PathBuf>,
}

fn parse_aggregate_command(
    args: &[String],
    default_children: impl FnOnce() -> Vec<ChildInput>,
) -> Result<AggregateCommandParts, Box<dyn Error>> {
    let mut child_proofs = Vec::new();
    let mut child_msgs = Vec::new();
    let mut proof_path = None;
    let mut proof_bytes_path = None;
    let mut public_path = None;
    let mut public_bytes_path = None;
    let mut vkey_path = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--child-proof" => {
                i += 1;
                child_proofs.push(next_path(args, i, "--child-proof")?);
            }
            "--child-msg" => {
                i += 1;
                child_msgs.push(next_path(args, i, "--child-msg")?);
            }
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
                return Err(format!("unknown aggregate argument: {other}\n\n{}", usage()).into())
            }
        }
        i += 1;
    }

    let children = if child_proofs.is_empty() && child_msgs.is_empty() {
        default_children()
    } else {
        child_proofs
            .into_iter()
            .map(ChildInput::Proof)
            .chain(child_msgs.into_iter().map(ChildInput::Msg))
            .collect()
    };

    if children.is_empty() {
        return Err("aggregate requires at least one child proof".into());
    }

    Ok(AggregateCommandParts {
        children,
        proof_path,
        proof_bytes_path,
        public_path,
        public_bytes_path,
        vkey_path,
    })
}

#[derive(Clone, Copy)]
enum AggregateKind {
    ProcessMessages,
    Tally,
}

impl AggregateKind {
    fn tag(self) -> u8 {
        match self {
            Self::ProcessMessages => 1,
            Self::Tally => 2,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ProcessMessages => "process-messages",
            Self::Tally => "tally",
        }
    }

    fn expected_output(
        self,
        child_public_outputs: &[Vec<u8>],
    ) -> Result<AggregatePublicOutput, Box<dyn Error>> {
        Ok(match self {
            Self::ProcessMessages => AggregatePublicOutput::ProcessMessages(
                build_process_messages_aggregate_public_output(child_public_outputs)?,
            ),
            Self::Tally => AggregatePublicOutput::Tally(build_tally_aggregate_public_output(
                child_public_outputs,
            )?),
        })
    }
}

fn parse_verify_compressed_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut proof_path = None;
    let mut proof_bytes_path = None;
    let mut public_bytes_path = None;
    let mut vkey_path = None;
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
                vkey_path = Some(next_path(args, i, "--vkey")?);
            }
            "--public" => {
                i += 1;
                public_path = Some(next_path(args, i, "--public")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => {
                return Err(
                    format!("unknown verify-compressed argument: {other}\n\n{}", usage()).into(),
                )
            }
        }
        i += 1;
    }

    if proof_path.is_none()
        && (proof_bytes_path.is_none() || public_bytes_path.is_none() || vkey_path.is_none())
    {
        return Err(format!(
            "verify-compressed requires either --proof PATH or --proof-bytes PATH --public-bytes PATH --vkey PATH\n\n{}",
            usage()
        )
        .into());
    }

    Ok(Command::VerifyCompressed {
        proof_path,
        proof_bytes_path,
        public_bytes_path,
        vkey_path,
        public_path,
    })
}

fn aggregate(
    kind: AggregateKind,
    children: &[ChildInput],
    proof_path: Option<&Path>,
    proof_bytes_path: Option<&Path>,
    public_path: Option<&Path>,
    public_bytes_path: Option<&Path>,
    vkey_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let (core_opts, shard_size) = compressed_core_opts()?;
    let client = ProverClient::builder().cpu().core_opts(core_opts).build();
    println!("shard_size={shard_size}");
    let child_pk = client.setup(AMACI_SP1_ELF)?;
    let aggregate_pk = client.setup(AMACI_SP1_AGGREGATE_ELF)?;

    let mut child_public_outputs = Vec::with_capacity(children.len());
    let mut child_recursion_proofs = Vec::with_capacity(children.len());
    for child in children {
        let loaded = load_child_compressed_proof(child)?;
        client.verify(&loaded.proof, child_pk.verifying_key(), None)?;
        let SP1Proof::Compressed(recursion_proof) = loaded.proof.proof else {
            return Err(format!("child proof is not compressed: {}", child.display()).into());
        };
        child_public_outputs.push(loaded.proof.public_values.to_vec());
        child_recursion_proofs.push(*recursion_proof);
    }

    let expected_output = kind.expected_output(&child_public_outputs)?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&kind.tag());
    stdin.write(&child_pk.verifying_key().hash_u32());
    stdin.write(&child_public_outputs);
    for proof in child_recursion_proofs {
        stdin.write_proof(proof, child_pk.verifying_key().vk.clone());
    }

    let proof = client.prove(&aggregate_pk, stdin).compressed().run()?;
    client.verify(&proof, aggregate_pk.verifying_key(), None)?;
    let proof_bytes = compressed_proof_bytes(&proof)?;
    let vkey_hash = compressed_vkey_hash_bytes(aggregate_pk.verifying_key());
    verify_compressed_artifacts(&proof_bytes, proof.public_values.as_slice(), &vkey_hash)?;

    let output = decode_aggregate_public_output(proof.public_values.as_slice())?;
    if output != expected_output {
        return Err("aggregate public values did not match expected child linkage output".into());
    }

    println!("aggregate={}", kind.name());
    println!("child_count={}", children.len());
    println!("public_bytes={}", proof.public_values.as_slice().len());
    println!("compressed_proof_bytes={}", proof_bytes.len());
    println!("compressed_vkey_bytes={}", vkey_hash.len());
    println!("vkey_hash={}", aggregate_pk.verifying_key().bytes32());
    println!("aggregate compressed verify ok");
    let public_json = serde_json::to_string_pretty(&output)?;
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
        write_parented(path, &vkey_hash)?;
        println!("vkey={}", path.display());
    }

    Ok(())
}

fn compressed_core_opts() -> Result<(SP1CoreOpts, usize), Box<dyn Error>> {
    let configured = env::var("SHARD_SIZE").ok();
    let shard_size = parse_compressed_shard_size(configured.as_deref())?;
    let mut opts = SP1CoreOpts::default();
    opts.shard_size = shard_size;
    Ok((opts, shard_size))
}

fn parse_compressed_shard_size(configured: Option<&str>) -> Result<usize, String> {
    let shard_size = match configured {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| format!("invalid SHARD_SIZE {value:?}: expected an integer"))?,
        None => DEFAULT_COMPRESSED_SHARD_SIZE,
    };
    if shard_size == 0 || shard_size > MAX_COMPRESSED_SHARD_SIZE || !shard_size.is_power_of_two() {
        return Err(format!(
            "invalid SHARD_SIZE {shard_size}: expected a power of two up to {MAX_COMPRESSED_SHARD_SIZE}"
        ));
    }
    Ok(shard_size)
}

fn verify_compressed(
    proof_path: Option<&Path>,
    proof_bytes_path: Option<&Path>,
    public_bytes_path: Option<&Path>,
    vkey_path: Option<&Path>,
    public_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let (proof_bytes, public_values, vkey_hash) = if let Some(path) = proof_path {
        let proof = SP1ProofWithPublicValues::load(path)?;
        let client = ProverClient::builder().cpu().build();
        let pk = client.setup(AMACI_SP1_AGGREGATE_ELF)?;
        client.verify(&proof, pk.verifying_key(), None)?;
        (
            compressed_proof_bytes(&proof)?,
            proof.public_values.to_vec(),
            compressed_vkey_hash_bytes(pk.verifying_key()),
        )
    } else {
        (
            fs::read(proof_bytes_path.expect("validated proof bytes path exists"))?,
            fs::read(public_bytes_path.expect("validated public bytes path exists"))?,
            fs::read(vkey_path.expect("validated vkey path exists"))?,
        )
    };

    verify_compressed_artifacts(&proof_bytes, &public_values, &vkey_hash)?;
    let output = decode_aggregate_public_output(&public_values)?;

    println!("aggregate compressed proof verify ok");
    println!("compressed_proof_bytes={}", proof_bytes.len());
    println!("public_bytes={}", public_values.len());
    println!("compressed_vkey_bytes={}", vkey_hash.len());
    let public_json = serde_json::to_string_pretty(&output)?;
    println!("{public_json}");

    if let Some(path) = public_path {
        write_parented(path, public_json.as_bytes())?;
        println!("public={}", path.display());
    }

    Ok(())
}

fn next_path(args: &[String], index: usize, flag: &str) -> Result<PathBuf, Box<dyn Error>> {
    args.get(index)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} requires a path").into())
}

#[derive(Clone)]
enum ChildInput {
    Proof(PathBuf),
    Msg(PathBuf),
}

impl ChildInput {
    fn display(&self) -> String {
        match self {
            Self::Proof(path) => path.display().to_string(),
            Self::Msg(path) => path.display().to_string(),
        }
    }
}

struct LoadedChildProof {
    proof: SP1ProofWithPublicValues,
}

fn load_child_compressed_proof(child: &ChildInput) -> Result<LoadedChildProof, Box<dyn Error>> {
    let proof = match child {
        ChildInput::Proof(path) => SP1ProofWithPublicValues::load(path)?,
        ChildInput::Msg(path) => {
            let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
            let msg = value
                .get("verify_compressed")
                .ok_or_else(|| format!("{} missing verify_compressed", path.display()))?;
            let proof_b64 = msg
                .get("proof")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{} missing verify_compressed.proof", path.display()))?;
            let public_b64 = msg
                .get("public_values")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!("{} missing verify_compressed.public_values", path.display())
                })?;
            let proof_bytes = base64::engine::general_purpose::STANDARD.decode(proof_b64)?;
            let public_values = base64::engine::general_purpose::STANDARD.decode(public_b64)?;
            let proof: SP1Proof = bincode::deserialize(&proof_bytes)?;
            SP1ProofWithPublicValues::new(
                proof,
                sp1_sdk::SP1PublicValues::from(&public_values),
                sp1_sdk::SP1_CIRCUIT_VERSION.to_string(),
            )
        }
    };
    Ok(LoadedChildProof { proof })
}

fn compressed_proof_bytes(proof: &SP1ProofWithPublicValues) -> Result<Vec<u8>, Box<dyn Error>> {
    match &proof.proof {
        SP1Proof::Compressed(_) => Ok(bincode::serialize(&proof.proof)?),
        other => Err(format!("expected compressed proof, got {other}").into()),
    }
}

fn compressed_vkey_hash_bytes(vk: &impl HashableKey) -> Vec<u8> {
    bincode::serialize(&vk.hash_koalabear())
        .expect("serializing compressed vkey hash should not fail")
}

fn verify_compressed_artifacts(
    proof_bytes: &[u8],
    public_values: &[u8],
    vkey_hash: &[u8],
) -> Result<(), Box<dyn Error>> {
    SP1CompressedVerifierRaw::verify_with_public_values(proof_bytes, public_values, vkey_hash)
        .map_err(|err| format!("aggregate compressed verification failed: {err}").into())
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

fn usage() -> &'static str {
    "usage:\n  amaci-proof-sp1-aggregate-host aggregate-process-messages [--child-proof PATH ...] [--child-msg PATH ...] [--proof PATH] [--proof-bytes PATH] [--public PATH] [--public-bytes PATH] [--vkey PATH]\n  amaci-proof-sp1-aggregate-host aggregate-tally [--child-proof PATH ...] [--child-msg PATH ...] [--proof PATH] [--proof-bytes PATH] [--public PATH] [--public-bytes PATH] [--vkey PATH]\n  amaci-proof-sp1-aggregate-host verify-compressed --proof PATH [--public PATH]\n  amaci-proof-sp1-aggregate-host verify-compressed --proof-bytes PATH --public-bytes PATH --vkey PATH [--public PATH]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_shard_size_defaults_to_benchmarked_value() {
        assert_eq!(parse_compressed_shard_size(None).unwrap(), 1 << 23);
    }

    #[test]
    fn compressed_shard_size_accepts_valid_override() {
        assert_eq!(
            parse_compressed_shard_size(Some("4194304")).unwrap(),
            1 << 22
        );
    }

    #[test]
    fn compressed_shard_size_rejects_invalid_values() {
        for value in ["0", "3", "33554432", "not-an-integer"] {
            assert!(parse_compressed_shard_size(Some(value)).is_err());
        }
    }
}
