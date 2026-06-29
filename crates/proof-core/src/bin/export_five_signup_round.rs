use amaci_proof_core::execute_proof_logic;
use amaci_proof_core::round_fixture::five_signup_round_fixture;
use serde::Serialize;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures/five-signup-round"));
    fs::create_dir_all(&out_dir)?;

    let fixture = five_signup_round_fixture()?;
    let mut manifest_stages = Vec::with_capacity(fixture.stages.len());
    for stage in &fixture.stages {
        let output = execute_proof_logic(&stage.input)?;
        let input_path = out_dir.join(format!("{}.input.json", stage.name));
        let public_path = out_dir.join(format!("{}.public.json", stage.name));
        write_json(&input_path, &stage.input)?;
        write_json(&public_path, &output)?;
        manifest_stages.push(StageManifest {
            name: stage.name.clone(),
            stage: stage.stage.clone(),
            circuit: stage.name.clone(),
            input_path: input_path
                .file_name()
                .expect("stage input path has file name")
                .to_string_lossy()
                .into_owned(),
            public_path: public_path
                .file_name()
                .expect("stage public path has file name")
                .to_string_lossy()
                .into_owned(),
            compressed_msg_path: format!("{}.verify-compressed.msg.json", stage.name),
        });
    }

    write_json(&out_dir.join("round.json"), &fixture)?;
    write_json(
        &out_dir.join("manifest.json"),
        &RoundManifest {
            round_id: fixture.round_id,
            initial_signups: fixture.initial_signups,
            final_signups: fixture.final_signups,
            expected_raw_results: fixture.expected_raw_results,
            stages: manifest_stages,
        },
    )?;
    println!("fixture={}", out_dir.display());
    Ok(())
}

#[derive(Serialize)]
struct RoundManifest {
    round_id: String,
    initial_signups: usize,
    final_signups: usize,
    expected_raw_results: [u128; 5],
    stages: Vec<StageManifest>,
}

#[derive(Serialize)]
struct StageManifest {
    name: String,
    stage: String,
    circuit: String,
    input_path: String,
    public_path: String,
    compressed_msg_path: String,
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}
