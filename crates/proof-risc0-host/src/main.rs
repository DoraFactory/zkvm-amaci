use amaci_proof_core::crypto::private_to_pub_key;
use amaci_proof_core::merkle::{root_from_path, state_leaf_hash, zero_root};
use amaci_proof_core::{
    execute_proof_logic, Field, ProcessMessagesInput, ProverInput, PublicOutput, TallyVotesInput,
};
use amaci_proof_risc0_methods::{AMACI_PROOF_RISC0_GUEST_ELF, AMACI_PROOF_RISC0_GUEST_ID};
use maci_crypto::{compute_input_hash, poseidon};
use num_bigint::BigUint;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

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
            .unwrap_or_else(|| "process-messages-2-1-5".to_string());
        Ok(Command::Prove {
            circuit,
            receipt_path: None,
            public_path: None,
        })
    }
}

fn parse_prove_command(args: &[String]) -> Result<Command, Box<dyn Error>> {
    let mut circuit = "process-messages-2-1-5".to_string();
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
    "usage:\n  amaci-proof-risc0-host [process-messages-2-1-5|tally-votes-2-1-1]\n  amaci-proof-risc0-host prove [circuit] [--receipt PATH] [--public PATH]\n  amaci-proof-risc0-host verify --receipt PATH [--public PATH]"
}

fn prove(
    circuit: &str,
    receipt_path: Option<&Path>,
    public_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let input = match circuit {
        "process-messages-2-1-5" | "process-messages" => {
            ProverInput::ProcessMessages(process_messages_2_1_5()?)
        }
        "tally-votes-2-1-1" | "tally-votes" => ProverInput::TallyVotes(tally_votes_2_1_1()?),
        other => {
            return Err(format!(
                "unsupported circuit {other}; use process-messages-2-1-5 or tally-votes-2-1-1"
            )
            .into());
        }
    };

    let expected_output = execute_proof_logic(&input)?;
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let prove_info = default_prover().prove(env, AMACI_PROOF_RISC0_GUEST_ELF)?;
    let receipt = prove_info.receipt;
    receipt.verify(AMACI_PROOF_RISC0_GUEST_ID)?;
    let journal_output: PublicOutput = receipt.journal.decode()?;
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
    let journal_output: PublicOutput = receipt.journal.decode()?;

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

fn process_messages_2_1_5() -> Result<ProcessMessagesInput, Box<dyn Error>> {
    let state_tree_depth = 2;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let coord_priv_key = one.clone();
    let coord_pub_key = private_to_pub_key(&coord_priv_key);

    let state_leaf = vec![zero.clone(); 10];
    let state_leaf_hash = state_leaf_hash(&state_leaf)?;
    let state_index = BigUint::from(24u32);
    let state_path = zero_sibling_path(state_tree_depth)?;
    let current_state_root = root_from_path(&state_leaf_hash, &state_index, &state_path)?;
    let current_state_salt = BigUint::from(11u32);
    let new_state_salt = BigUint::from(12u32);
    let current_state_commitment =
        poseidon(&[current_state_root.clone(), current_state_salt.clone()]);
    let new_state_commitment = poseidon(&[current_state_root.clone(), new_state_salt.clone()]);

    let active_state_root = zero_root(state_tree_depth)?;
    let deactivate_root = zero_root(state_tree_depth + 2)?;
    let deactivate_commitment = poseidon(&[active_state_root.clone(), deactivate_root.clone()]);

    let packed_vals = BigUint::from(5u32) + (BigUint::from(1u32) << 32usize);
    let expected_poll_id = one;
    let batch_start_hash = zero.clone();
    let batch_end_hash = zero.clone();
    let coord_pub_key_hash = poseidon(&coord_pub_key);
    let input_hash = compute_input_hash(&[
        packed_vals.clone(),
        coord_pub_key_hash,
        batch_start_hash.clone(),
        batch_end_hash.clone(),
        current_state_commitment.clone(),
        new_state_commitment.clone(),
        deactivate_commitment.clone(),
        expected_poll_id.clone(),
    ]);

    Ok(ProcessMessagesInput {
        state_tree_depth,
        vote_option_tree_depth,
        batch_size,
        input_hash,
        packed_vals,
        expected_poll_id,
        batch_start_hash,
        batch_end_hash,
        coord_priv_key,
        coord_pub_key,
        msgs: vec![vec![zero.clone(); 10]; batch_size],
        enc_pub_keys: vec![[zero.clone(), zero.clone()]; batch_size],
        current_state_root,
        current_state_leaves: vec![state_leaf; batch_size],
        current_state_leaves_path_elements: vec![state_path; batch_size],
        current_state_commitment,
        current_state_salt,
        new_state_commitment,
        new_state_salt,
        active_state_root,
        deactivate_root,
        deactivate_commitment,
        active_state_leaves: vec![zero.clone(); batch_size],
        active_state_leaves_path_elements: vec![zero_sibling_path(state_tree_depth)?; batch_size],
        current_vote_weights: vec![zero.clone(); batch_size],
        current_vote_weights_path_elements: vec![
            vec![vec![zero.clone(); 4]; vote_option_tree_depth];
            batch_size
        ],
    })
}

fn zero_sibling_path(depth: usize) -> Result<Vec<Vec<Field>>, Box<dyn Error>> {
    let mut path = Vec::with_capacity(depth);
    for level in 0..depth {
        path.push(vec![zero_root(level)?; 4]);
    }
    Ok(path)
}

fn tally_votes_2_1_1() -> Result<TallyVotesInput, Box<dyn Error>> {
    let state_tree_depth = 2;
    let int_state_tree_depth = 1;
    let vote_option_tree_depth = 1;
    let batch_size = 5;
    let num_vote_options = 5;
    let zero = BigUint::from(0u32);

    let zero_state_leaf = vec![zero.clone(); 10];
    let state_leaf_hash = state_leaf_hash(&zero_state_leaf)?;
    let state_subroot = poseidon(&vec![state_leaf_hash; batch_size]);
    let state_path_elements = vec![vec![zero.clone(); 4]];
    let state_root = root_from_path(&state_subroot, &zero, &state_path_elements)?;
    let state_salt = BigUint::from(21u32);
    let state_commitment = poseidon(&[state_root.clone(), state_salt.clone()]);

    let current_tally_commitment = zero.clone();
    let current_results = vec![zero.clone(); num_vote_options];
    let votes = vec![vec![zero.clone(); num_vote_options]; batch_size];
    let new_results_root_salt = BigUint::from(22u32);
    let new_results_root = poseidon(&current_results);
    let new_tally_commitment = poseidon(&[new_results_root, new_results_root_salt.clone()]);
    let packed_vals = BigUint::from(5u32) << 32usize;
    let input_hash = compute_input_hash(&[
        packed_vals.clone(),
        state_commitment.clone(),
        current_tally_commitment.clone(),
        new_tally_commitment.clone(),
    ]);

    Ok(TallyVotesInput {
        state_tree_depth,
        int_state_tree_depth,
        vote_option_tree_depth,
        input_hash,
        packed_vals,
        state_root,
        state_salt,
        state_commitment,
        current_tally_commitment,
        new_tally_commitment,
        state_leaf: vec![zero_state_leaf; batch_size],
        state_path_elements,
        votes,
        current_results,
        current_results_root_salt: zero,
        new_results_root_salt,
    })
}
