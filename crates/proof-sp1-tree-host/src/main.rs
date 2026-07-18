use amaci_proof_core::tree_aggregate::{
    build_tree_request_output, decode_tree_public_output, machine_vkey_digest_bytes,
    FinalizationRootPublicOutput, TreeAggregatePublicOutput, TreeAggregateRequest,
    TreeAggregateRequestKind, TreeProgramIdentity, TREE_FANOUT,
};
use base64::Engine;
use serde::Serialize;
use serde_json::json;
use sp1_core_executor::SP1CoreOpts;
use sp1_sdk::blocking::{CpuProver, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{
    include_elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey,
};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const AMACI_SP1_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-program");
const AMACI_SP1_TREE_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-tree-program");
const DEFAULT_COMPRESSED_SHARD_SIZE: usize = 1 << 23;
const MAX_COMPRESSED_SHARD_SIZE: usize = 1 << 24;

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args)? {
        Command::BuildFinalization(args) => build_finalization(args)?,
        Command::VerifyFinalization(args) => verify_finalization(args)?,
    }
    Ok(())
}

enum Command {
    BuildFinalization(BuildFinalizationArgs),
    VerifyFinalization(VerifyFinalizationArgs),
}

struct BuildFinalizationArgs {
    process_children: Vec<PathBuf>,
    tally_children: Vec<PathBuf>,
    output_dir: PathBuf,
}

struct VerifyFinalizationArgs {
    proof: Option<PathBuf>,
    proof_bytes: Option<PathBuf>,
    public_bytes: Option<PathBuf>,
    vkey: Option<PathBuf>,
}

fn parse_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("build-finalization") => {
            parse_build_finalization(&args[1..]).map(Command::BuildFinalization)
        }
        Some("verify-finalization") => {
            parse_verify_finalization(&args[1..]).map(Command::VerifyFinalization)
        }
        Some("--help") | Some("-h") | None => Err(usage().into()),
        Some(other) => Err(format!("unknown command: {other}\n\n{}", usage()).into()),
    }
}

fn parse_build_finalization(args: &[String]) -> Result<BuildFinalizationArgs, Box<dyn Error>> {
    let mut process_children = Vec::new();
    let mut tally_children = Vec::new();
    let mut output_dir = PathBuf::from("sp1-proofs/tree-finalization");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--process-child" => {
                i += 1;
                process_children.push(next_path(args, i, "--process-child")?);
            }
            "--tally-child" => {
                i += 1;
                tally_children.push(next_path(args, i, "--tally-child")?);
            }
            "--output-dir" => {
                i += 1;
                output_dir = next_path(args, i, "--output-dir")?;
            }
            "--help" | "-h" => return Err(usage().into()),
            other => return Err(format!("unknown build-finalization argument: {other}").into()),
        }
        i += 1;
    }
    if process_children.is_empty() || tally_children.is_empty() {
        return Err("build-finalization requires process-message and tally child proofs".into());
    }
    Ok(BuildFinalizationArgs {
        process_children,
        tally_children,
        output_dir,
    })
}

fn parse_verify_finalization(args: &[String]) -> Result<VerifyFinalizationArgs, Box<dyn Error>> {
    let mut proof = None;
    let mut proof_bytes = None;
    let mut public_bytes = None;
    let mut vkey = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--proof" => {
                i += 1;
                proof = Some(next_path(args, i, "--proof")?);
            }
            "--proof-bytes" => {
                i += 1;
                proof_bytes = Some(next_path(args, i, "--proof-bytes")?);
            }
            "--public-bytes" => {
                i += 1;
                public_bytes = Some(next_path(args, i, "--public-bytes")?);
            }
            "--vkey" => {
                i += 1;
                vkey = Some(next_path(args, i, "--vkey")?);
            }
            "--help" | "-h" => return Err(usage().into()),
            other => return Err(format!("unknown verify-finalization argument: {other}").into()),
        }
        i += 1;
    }
    if proof.is_none() && (proof_bytes.is_none() || public_bytes.is_none() || vkey.is_none()) {
        return Err("verify-finalization requires --proof or all raw artifact paths".into());
    }
    Ok(VerifyFinalizationArgs {
        proof,
        proof_bytes,
        public_bytes,
        vkey,
    })
}

#[derive(Clone, Copy)]
enum StageTree {
    ProcessMessages,
    Tally,
}

impl StageTree {
    fn dir_name(self) -> &'static str {
        match self {
            Self::ProcessMessages => "process-messages",
            Self::Tally => "tally",
        }
    }

    fn request_kind(self, leaf: bool) -> TreeAggregateRequestKind {
        match (self, leaf) {
            (Self::ProcessMessages, true) => TreeAggregateRequestKind::ProcessMessagesLeaf,
            (Self::ProcessMessages, false) => TreeAggregateRequestKind::ProcessMessagesInternal,
            (Self::Tally, true) => TreeAggregateRequestKind::TallyLeaf,
            (Self::Tally, false) => TreeAggregateRequestKind::TallyInternal,
        }
    }
}

struct ProofArtifact {
    proof: SP1ProofWithPublicValues,
    proof_path: PathBuf,
}

struct StageRoot {
    artifact: ProofArtifact,
    level_count: u32,
    leaf_count: u32,
}

#[derive(Serialize)]
struct BuildManifest {
    fanout: usize,
    process_messages_leaf_count: u32,
    tally_leaf_count: u32,
    process_messages_levels: u32,
    tally_levels: u32,
    process_messages_level_widths: Vec<usize>,
    tally_level_widths: Vec<usize>,
    recursive_node_count: usize,
    base_program_vkey_digest: String,
    tree_program_vkey_digest: String,
    base_compressed_vkey_hash: String,
    tree_compressed_vkey_hash: String,
    process_messages_root: String,
    tally_root: String,
    finalization_root: String,
    contract_config: String,
    close_checkpoint: String,
    execute_msg: String,
}

fn build_finalization(args: BuildFinalizationArgs) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&args.output_dir)?;
    let process_level_widths = tree_level_widths(args.process_children.len());
    let tally_level_widths = tree_level_widths(args.tally_children.len());
    let recursive_node_count =
        process_level_widths.iter().sum::<usize>() + tally_level_widths.iter().sum::<usize>() + 1;
    println!("process_messages_level_widths={process_level_widths:?}");
    println!("tally_level_widths={tally_level_widths:?}");
    println!("recursive_node_count={recursive_node_count}");
    let (core_opts, shard_size) = compressed_core_opts()?;
    let client = ProverClient::builder().cpu().core_opts(core_opts).build();
    println!("shard_size={shard_size}");
    let base_pk = client.setup(AMACI_SP1_ELF)?;
    let tree_pk = client.setup(AMACI_SP1_TREE_ELF)?;
    let base_vkey_words = base_pk.verifying_key().hash_u32();
    let tree_vkey_words = tree_pk.verifying_key().hash_u32();
    let identity = TreeProgramIdentity {
        base_program_vkey: machine_vkey_digest_bytes(&base_vkey_words),
        tree_program_vkey: machine_vkey_digest_bytes(&tree_vkey_words),
    };

    let process_root = build_stage_tree(
        &client,
        &base_pk,
        &tree_pk,
        &identity,
        StageTree::ProcessMessages,
        &args.process_children,
        &args.output_dir,
    )?;
    let tally_root = build_stage_tree(
        &client,
        &base_pk,
        &tree_pk,
        &identity,
        StageTree::Tally,
        &args.tally_children,
        &args.output_dir,
    )?;

    let finalization_children = vec![
        ProofArtifact {
            proof: process_root.artifact.proof,
            proof_path: process_root.artifact.proof_path.clone(),
        },
        ProofArtifact {
            proof: tally_root.artifact.proof,
            proof_path: tally_root.artifact.proof_path.clone(),
        },
    ];
    let finalization_request = TreeAggregateRequest {
        kind: TreeAggregateRequestKind::FinalizationRoot,
        identity: identity.clone(),
        child_vkey_digests: vec![tree_vkey_words, tree_vkey_words],
        child_public_outputs: finalization_children
            .iter()
            .map(|child| child.proof.public_values.to_vec())
            .collect(),
    };
    let finalization_prefix = args.output_dir.join("finalization-root");
    let finalization_root = prove_request(
        &client,
        &tree_pk,
        &finalization_children,
        &[&tree_pk, &tree_pk],
        finalization_request,
        &finalization_prefix,
    )?;
    let finalization_output =
        match decode_tree_public_output(finalization_root.proof.public_values.as_slice())? {
            TreeAggregatePublicOutput::FinalizationRoot(output) => output,
            _ => return Err("tree host produced a non-finalization proof".into()),
        };
    write_contract_artifacts(
        &args.output_dir,
        &finalization_root.proof,
        &base_pk,
        &tree_pk,
        &finalization_output,
    )?;

    let tree_vkey_hash = compressed_vkey_hash_bytes(tree_pk.verifying_key());
    let contract_config_path = args.output_dir.join("contract-config.json");
    let close_checkpoint_path = args.output_dir.join("close-checkpoint.json");
    let execute_msg_path = args
        .output_dir
        .join("finalization-root.verify-compressed.msg.json");
    let manifest = BuildManifest {
        fanout: TREE_FANOUT,
        process_messages_leaf_count: process_root.leaf_count,
        tally_leaf_count: tally_root.leaf_count,
        process_messages_levels: process_root.level_count,
        tally_levels: tally_root.level_count,
        process_messages_level_widths: process_level_widths,
        tally_level_widths,
        recursive_node_count,
        base_program_vkey_digest: hex_bytes(&identity.base_program_vkey),
        tree_program_vkey_digest: hex_bytes(&identity.tree_program_vkey),
        base_compressed_vkey_hash: hex_bytes(&compressed_vkey_hash_bytes(base_pk.verifying_key())),
        tree_compressed_vkey_hash: hex_bytes(&tree_vkey_hash),
        process_messages_root: process_root.artifact.proof_path.display().to_string(),
        tally_root: tally_root.artifact.proof_path.display().to_string(),
        finalization_root: finalization_root.proof_path.display().to_string(),
        contract_config: contract_config_path.display().to_string(),
        close_checkpoint: close_checkpoint_path.display().to_string(),
        execute_msg: execute_msg_path.display().to_string(),
    };
    atomic_write(
        &args.output_dir.join("manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&manifest)?).as_bytes(),
    )?;

    println!("tree finalization build ok");
    println!("fanout={TREE_FANOUT}");
    println!("process_messages_leaf_count={}", process_root.leaf_count);
    println!("process_messages_levels={}", process_root.level_count);
    println!("tally_leaf_count={}", tally_root.leaf_count);
    println!("tally_levels={}", tally_root.level_count);
    println!(
        "finalization_root={}",
        finalization_root.proof_path.display()
    );
    println!("contract_config={}", contract_config_path.display());
    println!("close_checkpoint={}", close_checkpoint_path.display());
    println!("execute_msg={}", execute_msg_path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_stage_tree(
    client: &CpuProver,
    base_pk: &SP1ProvingKey,
    tree_pk: &SP1ProvingKey,
    identity: &TreeProgramIdentity,
    stage: StageTree,
    child_paths: &[PathBuf],
    output_dir: &Path,
) -> Result<StageRoot, Box<dyn Error>> {
    let mut current_paths = child_paths.to_vec();
    let leaf_count: u32 = current_paths.len().try_into()?;
    let mut level = 1u32;
    let mut leaf_level = true;

    loop {
        let mut next_paths = Vec::with_capacity(current_paths.len().div_ceil(TREE_FANOUT));
        for (node_index, child_paths) in current_paths.chunks(TREE_FANOUT).enumerate() {
            let child_pk = if leaf_level { base_pk } else { tree_pk };
            let children = child_paths
                .iter()
                .map(|path| load_and_verify(client, path, child_pk))
                .collect::<Result<Vec<_>, _>>()?;
            let child_vkey = child_pk.verifying_key().hash_u32();
            let request = TreeAggregateRequest {
                kind: stage.request_kind(leaf_level),
                identity: identity.clone(),
                child_vkey_digests: vec![child_vkey; children.len()],
                child_public_outputs: children
                    .iter()
                    .map(|child| child.proof.public_values.to_vec())
                    .collect(),
            };
            let prefix = output_dir
                .join(stage.dir_name())
                .join(format!("level-{level:03}"))
                .join(format!("node-{node_index:05}"));
            let child_pks = vec![child_pk; children.len()];
            let node = prove_request(client, tree_pk, &children, &child_pks, request, &prefix)?;
            next_paths.push(node.proof_path);
        }
        if next_paths.len() == 1 {
            let root = load_and_verify(client, &next_paths[0], tree_pk)?;
            let root_prefix = output_dir.join(stage.dir_name()).join("root");
            write_artifacts(&root_prefix, &root.proof, tree_pk, 0)?;
            return Ok(StageRoot {
                artifact: root,
                level_count: level,
                leaf_count,
            });
        }
        current_paths = next_paths;
        leaf_level = false;
        level = level
            .checked_add(1)
            .ok_or("tree level overflow while building stage")?;
    }
}

fn prove_request(
    client: &CpuProver,
    tree_pk: &SP1ProvingKey,
    children: &[ProofArtifact],
    child_pks: &[&SP1ProvingKey],
    request: TreeAggregateRequest,
    prefix: &Path,
) -> Result<ProofArtifact, Box<dyn Error>> {
    let expected = build_tree_request_output(&request)?;
    let proof_path = artifact_path(prefix, ".proof.bin");
    if proof_path.is_file() {
        if let Ok(proof) = SP1ProofWithPublicValues::load(&proof_path) {
            let valid = client.verify(&proof, tree_pk.verifying_key(), None).is_ok()
                && decode_tree_public_output(proof.public_values.as_slice())
                    .is_ok_and(|actual| actual == expected);
            if valid {
                write_artifacts(prefix, &proof, tree_pk, 0)?;
                println!("resume={}", proof_path.display());
                return Ok(ProofArtifact { proof, proof_path });
            }
        }
        println!("cache_incompatible={}", proof_path.display());
    }

    if children.len() != child_pks.len() {
        return Err("tree child proof/key length mismatch".into());
    }
    let mut stdin = SP1Stdin::new();
    stdin.write(&request);
    for (child, child_pk) in children.iter().zip(child_pks) {
        client.verify(&child.proof, child_pk.verifying_key(), None)?;
        let SP1Proof::Compressed(recursion_proof) = &child.proof.proof else {
            return Err(format!(
                "child proof is not compressed: {}",
                child.proof_path.display()
            )
            .into());
        };
        stdin.write_proof(
            recursion_proof.as_ref().clone(),
            child_pk.verifying_key().vk.clone(),
        );
    }

    let started = Instant::now();
    let proof = client.prove(tree_pk, stdin).compressed().run()?;
    let elapsed_ms = started.elapsed().as_millis();
    client.verify(&proof, tree_pk.verifying_key(), None)?;
    let actual = decode_tree_public_output(proof.public_values.as_slice())?;
    if actual != expected {
        return Err("tree proof public output did not match expected output".into());
    }
    write_artifacts(prefix, &proof, tree_pk, elapsed_ms)?;
    println!("node={}", proof_path.display());
    println!("node_elapsed_ms={elapsed_ms}");
    Ok(ProofArtifact { proof, proof_path })
}

fn load_and_verify(
    client: &CpuProver,
    path: &Path,
    pk: &SP1ProvingKey,
) -> Result<ProofArtifact, Box<dyn Error>> {
    let proof = SP1ProofWithPublicValues::load(path)?;
    client.verify(&proof, pk.verifying_key(), None)?;
    if !matches!(proof.proof, SP1Proof::Compressed(_)) {
        return Err(format!("proof is not compressed: {}", path.display()).into());
    }
    Ok(ProofArtifact {
        proof,
        proof_path: path.to_path_buf(),
    })
}

fn write_artifacts(
    prefix: &Path,
    proof: &SP1ProofWithPublicValues,
    tree_pk: &SP1ProvingKey,
    elapsed_ms: u128,
) -> Result<(), Box<dyn Error>> {
    let proof_path = artifact_path(prefix, ".proof.bin");
    atomic_save_proof(&proof_path, proof)?;
    atomic_write(
        &artifact_path(prefix, ".proof.bytes"),
        &compressed_proof_bytes(proof)?,
    )?;
    atomic_write(
        &artifact_path(prefix, ".public.bin"),
        proof.public_values.as_slice(),
    )?;
    let output = decode_tree_public_output(proof.public_values.as_slice())?;
    atomic_write(
        &artifact_path(prefix, ".public.json"),
        format!("{}\n", serde_json::to_string_pretty(&output)?).as_bytes(),
    )?;
    atomic_write(
        &artifact_path(prefix, ".vkey.bin"),
        &compressed_vkey_hash_bytes(tree_pk.verifying_key()),
    )?;
    let (direct_child_count, leaf_count, level) = output_metrics(&output);
    let metrics = json!({
        "elapsed_ms": elapsed_ms,
        "direct_child_count": direct_child_count,
        "leaf_count": leaf_count,
        "level": level,
        "proof_bytes": compressed_proof_bytes(proof)?.len(),
        "public_bytes": proof.public_values.as_slice().len(),
    });
    atomic_write(
        &artifact_path(prefix, ".metrics.json"),
        format!("{}\n", serde_json::to_string_pretty(&metrics)?).as_bytes(),
    )?;
    Ok(())
}

fn write_contract_artifacts(
    output_dir: &Path,
    proof: &SP1ProofWithPublicValues,
    base_pk: &SP1ProvingKey,
    tree_pk: &SP1ProvingKey,
    output: &FinalizationRootPublicOutput,
) -> Result<(), Box<dyn Error>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let proof_bytes = compressed_proof_bytes(proof)?;
    let tree_vkey_hash = compressed_vkey_hash_bytes(tree_pk.verifying_key());
    let config = json!({
        "base_vkey_hash": b64.encode(compressed_vkey_hash_bytes(base_pk.verifying_key())),
        "tree_vkey_hash": b64.encode(&tree_vkey_hash),
        "base_program_vkey_digest": b64.encode(output.identity.base_program_vkey),
        "tree_program_vkey_digest": b64.encode(output.identity.tree_program_vkey),
        "expected_poll_id": b64.encode(output.expected_poll_id),
        "expected_coord_pub_key_hash": b64.encode(output.coord_pub_key_hash),
    });
    atomic_write(
        &output_dir.join("contract-config.json"),
        format!("{}\n", serde_json::to_string_pretty(&config)?).as_bytes(),
    )?;
    let checkpoint = json!({
        "initial_state_commitment": b64.encode(output.initial_state_commitment),
        "message_batch_start_hash": b64.encode(output.initial_batch_start_hash),
        "message_batch_end_hash": b64.encode(output.final_batch_end_hash),
    });
    atomic_write(
        &output_dir.join("close-checkpoint.json"),
        format!("{}\n", serde_json::to_string_pretty(&checkpoint)?).as_bytes(),
    )?;
    let msg = json!({
        "verify_compressed_finalization_root": {
            "proof": b64.encode(proof_bytes),
            "public_values": b64.encode(proof.public_values.as_slice()),
        }
    });
    atomic_write(
        &output_dir.join("finalization-root.verify-compressed.msg.json"),
        format!("{}\n", serde_json::to_string(&msg)?).as_bytes(),
    )?;
    Ok(())
}

fn verify_finalization(args: VerifyFinalizationArgs) -> Result<(), Box<dyn Error>> {
    let (proof_bytes, public_values, vkey_hash) = if let Some(path) = args.proof {
        let proof = SP1ProofWithPublicValues::load(path)?;
        let client = ProverClient::builder().cpu().build();
        let tree_pk = client.setup(AMACI_SP1_TREE_ELF)?;
        client.verify(&proof, tree_pk.verifying_key(), None)?;
        (
            compressed_proof_bytes(&proof)?,
            proof.public_values.to_vec(),
            compressed_vkey_hash_bytes(tree_pk.verifying_key()),
        )
    } else {
        (
            fs::read(args.proof_bytes.expect("validated raw proof path"))?,
            fs::read(args.public_bytes.expect("validated public path"))?,
            fs::read(args.vkey.expect("validated vkey path"))?,
        )
    };
    SP1CompressedVerifierRaw::verify_with_public_values(&proof_bytes, &public_values, &vkey_hash)?;
    let output = decode_tree_public_output(&public_values)?;
    if !matches!(output, TreeAggregatePublicOutput::FinalizationRoot(_)) {
        return Err("verified tree proof is not a finalization root".into());
    }
    println!("tree finalization proof verify ok");
    println!("proof_bytes={}", proof_bytes.len());
    println!("public_bytes={}", public_values.len());
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn output_metrics(output: &TreeAggregatePublicOutput) -> (u32, u32, u32) {
    match output {
        TreeAggregatePublicOutput::ProcessMessages(output) => {
            (output.direct_child_count, output.leaf_count, output.level)
        }
        TreeAggregatePublicOutput::Tally(output) => {
            (output.direct_child_count, output.leaf_count, output.level)
        }
        TreeAggregatePublicOutput::FinalizationRoot(output) => {
            (output.direct_child_count, output.total_leaf_count, 0)
        }
    }
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

fn artifact_path(prefix: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{}", prefix.display(), suffix))
}

fn atomic_save_proof(path: &Path, proof: &SP1ProofWithPublicValues) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = artifact_path(path, ".tmp");
    proof.save(&temp)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = artifact_path(path, ".tmp");
    fs::write(&temp, bytes)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn next_path(args: &[String], index: usize, flag: &str) -> Result<PathBuf, Box<dyn Error>> {
    args.get(index)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} requires a path").into())
}

fn tree_level_widths(mut child_count: usize) -> Vec<usize> {
    debug_assert!(child_count > 0);
    let mut widths = Vec::new();
    loop {
        child_count = child_count.div_ceil(TREE_FANOUT);
        widths.push(child_count);
        if child_count == 1 {
            return widths;
        }
    }
}

fn usage() -> &'static str {
    "usage:\n  amaci-proof-sp1-tree-host build-finalization --process-child PATH ... --tally-child PATH ... [--output-dir DIR]\n  amaci-proof-sp1-tree-host verify-finalization --proof PATH\n  amaci-proof-sp1-tree-host verify-finalization --proof-bytes PATH --public-bytes PATH --vkey PATH"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_level_plan_has_fixed_fanout() {
        assert_eq!(tree_level_widths(1), vec![1]);
        assert_eq!(tree_level_widths(5), vec![1]);
        assert_eq!(tree_level_widths(6), vec![2, 1]);
        assert_eq!(tree_level_widths(25), vec![5, 1]);
        assert_eq!(tree_level_widths(26), vec![6, 2, 1]);
        assert_eq!(tree_level_widths(126), vec![26, 6, 2, 1]);
    }

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
