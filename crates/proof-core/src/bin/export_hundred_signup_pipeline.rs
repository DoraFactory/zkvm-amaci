use amaci_proof_core::codec::{encode_input, encode_public_output};
use amaci_proof_core::execute_proof_logic;
use amaci_proof_core::round_fixture::hundred_signup_round_fixture;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;
const TREE_FANOUT: usize = 5;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sp1-work/hundred-signup-9-3-1-5"));
    let source_revision = env::args().nth(2).unwrap_or_else(|| "unknown".to_string());
    let checksum = export_hundred_signup_pipeline(&out_dir, &source_revision)?;
    println!("pipeline={}", out_dir.display());
    println!("checksums_sha256={checksum}");
    Ok(())
}

fn export_hundred_signup_pipeline(
    out_dir: &Path,
    source_revision: &str,
) -> Result<String, Box<dyn Error>> {
    let fixture = hundred_signup_round_fixture()?;
    let input_dir = out_dir.join("inputs");
    let expected_dir = out_dir.join("expected-public");
    fs::create_dir_all(&input_dir)?;
    fs::create_dir_all(&expected_dir)?;

    let mut tasks = Vec::with_capacity(fixture.stages.len());
    let mut checksum_paths = Vec::with_capacity(fixture.stages.len() * 4 + 2);
    for (index, stage) in fixture.stages.iter().enumerate() {
        let output = execute_proof_logic(&stage.input)?;
        let input_bin = format!("inputs/{}.input.bin", stage.name);
        let input_json = format!("inputs/{}.input.json", stage.name);
        let public_bin = format!("expected-public/{}.public.bin", stage.name);
        let public_json = format!("expected-public/{}.public.json", stage.name);
        write_bytes(&out_dir.join(&input_bin), &encode_input(&stage.input))?;
        write_json(&out_dir.join(&input_json), &stage.input)?;
        write_bytes(&out_dir.join(&public_bin), &encode_public_output(&output))?;
        write_json(&out_dir.join(&public_json), &output)?;
        checksum_paths.extend([
            input_bin.clone(),
            input_json,
            public_bin.clone(),
            public_json,
        ]);
        tasks.push(PipelineTask {
            index,
            name: stage.name.clone(),
            stage: stage.stage.clone(),
            input_path: input_bin,
            expected_public_path: public_bin,
            artifact_dir: format!("artifacts/{}", stage.name),
        });
    }

    let manifest = PipelineManifest {
        schema_version: SCHEMA_VERSION,
        source_revision: source_revision.to_string(),
        round_id: fixture.round_id,
        profile: "9-3-1-5".to_string(),
        tree_fanout: TREE_FANOUT,
        state_tree_depth: fixture.state_tree_depth,
        vote_option_tree_depth: fixture.vote_option_tree_depth,
        process_message_batch_size: fixture.process_message_batch_size,
        tally_batch_size: fixture.tally_batch_size,
        initial_signups: fixture.initial_signups,
        final_signups: fixture.final_signups,
        message_count: fixture.message_count,
        expected_raw_results: fixture.expected_raw_results,
        tasks,
    };
    write_json(&out_dir.join("manifest.json"), &manifest)?;
    write_tasks_tsv(&out_dir.join("tasks.tsv"), &manifest.tasks)?;
    checksum_paths.extend(["manifest.json".to_string(), "tasks.tsv".to_string()]);
    checksum_paths.sort();

    let mut checksum_file = String::new();
    for relative in checksum_paths {
        let digest = sha256_file(&out_dir.join(&relative))?;
        checksum_file.push_str(&format!("{digest}  {relative}\n"));
    }
    write_bytes(&out_dir.join("checksums.sha256"), checksum_file.as_bytes())?;
    sha256_file(&out_dir.join("checksums.sha256"))
}

#[derive(Debug, Serialize, Deserialize)]
struct PipelineManifest {
    schema_version: u32,
    source_revision: String,
    round_id: String,
    profile: String,
    tree_fanout: usize,
    state_tree_depth: usize,
    vote_option_tree_depth: usize,
    process_message_batch_size: usize,
    tally_batch_size: usize,
    initial_signups: usize,
    final_signups: usize,
    message_count: usize,
    expected_raw_results: [u128; 5],
    tasks: Vec<PipelineTask>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PipelineTask {
    index: usize,
    name: String,
    stage: String,
    input_path: String,
    expected_public_path: String,
    artifact_dir: String,
}

fn write_tasks_tsv(path: &Path, tasks: &[PipelineTask]) -> Result<(), Box<dyn Error>> {
    let mut output =
        "index\tname\tstage\tinput_path\texpected_public_path\tartifact_dir\n".to_string();
    for task in tasks {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            task.index,
            task.name,
            task.stage,
            task.input_path,
            task.expected_public_path,
            task.artifact_dir
        ));
    }
    write_bytes(path, output.as_bytes())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    write_bytes(
        path,
        format!("{}\n", serde_json::to_string_pretty(value)?).as_bytes(),
    )
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path)?);
    Ok(hex_bytes(&hasher.finalize()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaci_proof_core::codec::{decode_input, decode_public_output};
    use amaci_proof_core::round_fixture::RoundStageInput;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn exports_frozen_hundred_signup_tasks_and_checksums() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let out_dir = env::temp_dir().join(format!(
            "amaci-hundred-pipeline-{}-{unique}",
            std::process::id()
        ));
        let checksum = export_hundred_signup_pipeline(&out_dir, "test-revision").unwrap();

        let manifest: PipelineManifest =
            serde_json::from_slice(&fs::read(out_dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.source_revision, "test-revision");
        assert_eq!(manifest.profile, "9-3-1-5");
        assert_eq!(manifest.tasks.len(), 23);
        assert_eq!(
            manifest
                .tasks
                .iter()
                .filter(|task| task.stage == "process_messages")
                .count(),
            20
        );
        assert_eq!(
            manifest
                .tasks
                .iter()
                .filter(|task| task.stage == "tally")
                .count(),
            1
        );

        let first = &manifest.tasks[0];
        let first_input =
            decode_input(&fs::read(out_dir.join(&first.input_path)).unwrap()).unwrap();
        assert_eq!(
            execute_proof_logic(&first_input).unwrap(),
            decode_public_output(&fs::read(out_dir.join(&first.expected_public_path)).unwrap())
                .unwrap()
        );
        assert_eq!(
            checksum,
            sha256_file(&out_dir.join("checksums.sha256")).unwrap()
        );

        for line in fs::read_to_string(out_dir.join("checksums.sha256"))
            .unwrap()
            .lines()
        {
            let (expected, relative) = line.split_once("  ").unwrap();
            assert_eq!(expected, sha256_file(&out_dir.join(relative)).unwrap());
        }
        fs::remove_dir_all(out_dir).unwrap();
    }

    #[test]
    fn stage_names_are_safe_for_tsv_and_paths() {
        let fixture = hundred_signup_round_fixture().unwrap();
        for RoundStageInput { name, stage, .. } in fixture.stages {
            assert!(!name.contains(['\t', '\n', '/']));
            assert!(!stage.contains(['\t', '\n', '/']));
        }
    }
}
