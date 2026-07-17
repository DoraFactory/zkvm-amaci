use sp1_sdk::blocking::{Prover, ProverClient, SP1Stdin};
use sp1_sdk::include_elf;
use std::env;
use std::error::Error;

const PROFILE_ELF: sp1_sdk::Elf = include_elf!("amaci-proof-sp1-crypto-profile-program");

#[derive(Clone, Copy)]
struct Op {
    id: u8,
    name: &'static str,
    default_iters: u32,
}

const OPS: &[Op] = &[
    Op {
        id: 1,
        name: "kem-decap",
        default_iters: 10,
    },
    Op {
        id: 2,
        name: "kem-encap",
        default_iters: 10,
    },
    Op {
        id: 6,
        name: "kem-decap-reuse",
        default_iters: 10,
    },
    Op {
        id: 3,
        name: "mldsa-verify",
        default_iters: 10,
    },
    Op {
        id: 4,
        name: "kem-compact",
        default_iters: 100,
    },
    Op {
        id: 5,
        name: "command-decrypt",
        default_iters: 100,
    },
];

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = env::args().skip(1).collect::<Vec<_>>();
    let (op_name, iters) = parse_args(&args)?;
    let op = OPS
        .iter()
        .copied()
        .find(|op| op.name == op_name)
        .ok_or_else(|| format!("unknown op {op_name}; supported: {}", supported_ops()))?;
    let iters = iters.unwrap_or(op.default_iters);

    let client = ProverClient::builder().cpu().build();
    let mut stdin = SP1Stdin::new();
    let input = encode_input(op.id, iters);
    println!("op={}", op.name);
    println!("iters={iters}");
    println!("input_bytes={}", input.len());
    stdin.write_vec(input);

    let (public_values, report) = client.execute(PROFILE_ELF, stdin).run()?;
    println!("public_bytes={}", public_values.as_slice().len());
    println!("output_digest={}", hex(public_values.as_slice()));
    println!("instructions={}", report.total_instruction_count());
    println!(
        "instructions_per_iter={:.3}",
        report.total_instruction_count() as f64 / iters as f64
    );
    println!("syscalls={}", report.total_syscall_count());
    println!(
        "touched_memory_addresses={}",
        report.touched_memory_addresses
    );
    if let Some(gas) = report.gas() {
        println!("gas={gas}");
    }
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(&str, Option<u32>), Box<dyn Error>> {
    if args.first().map(String::as_str) == Some("--help")
        || args.first().map(String::as_str) == Some("-h")
    {
        return Err(usage().into());
    }
    let op = args.first().map(String::as_str).unwrap_or("kem-decap");
    let mut iters = None;
    let mut i = usize::from(!args.is_empty());
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                i += 1;
                iters = Some(
                    args.get(i)
                        .ok_or("missing value after --iters")?
                        .parse::<u32>()?,
                );
            }
            other => return Err(format!("unknown argument: {other}\n\n{}", usage()).into()),
        }
        i += 1;
    }
    Ok((op, iters))
}

fn usage() -> String {
    format!(
        "usage:\n  amaci-proof-sp1-crypto-profile-host [op] [--iters N]\n\nsupported ops: {}",
        supported_ops()
    )
}

fn supported_ops() -> String {
    OPS.iter().map(|op| op.name).collect::<Vec<_>>().join(", ")
}

fn encode_input(op: u8, iters: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(op);
    out.extend_from_slice(&iters.to_be_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
