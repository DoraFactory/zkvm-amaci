# zkVM AMACI

This repository contains the Rust zkVM migration of the AMACI Circom circuits.

The implementation keeps AMACI circuit logic in a zkVM-independent Rust core, then exposes thin adapters for RISC Zero and SP1. The current goal is proof-pipeline closure first: prove that the migrated Rust logic can run inside zkVM guests, produce stable public outputs, save proof artifacts, and verify those artifacts with local zkVM verifiers.

## Status

Implemented:

- Rust `proof-core` logic for the four AMACI top-level circuits:
  - `ProcessMessages`
  - `TallyVotes`
  - `ProcessDeactivateMessages`
  - `AddNewKey`
- Golden and negative tests against current fixtures.
- RISC Zero guest, host prover, receipt artifact output, and independent local verifier CLI.
- SP1 guest program, host prover, proof artifact output, and independent local verifier CLI.

Current built-in zkVM host inputs:

- `process-messages-2-1-5`
- `tally-votes-2-1-1`

The remaining AMACI circuits are implemented in `proof-core`, but their built-in zkVM prover inputs are not wired into the host CLIs yet.

## Workspace Layout

```text
zkvm-amaci/
  crates/
    proof-core/            # zkVM-independent AMACI circuit logic
    proof-risc0-guest/     # RISC Zero guest wrapper
    proof-risc0-methods/   # RISC Zero ELF/image ID build crate
    proof-risc0-host/      # RISC Zero prove/verify CLI
    proof-sp1-program/     # SP1 guest program
    proof-sp1-host/        # SP1 prove/verify CLI
    baby-jubjub/           # vendored crypto dependency
    eddsa-poseidon/        # vendored crypto dependency
    maci-crypto/           # vendored AMACI crypto helpers
  docs/
    risc0_proving_runbook.md
    sp1_proving_runbook.md
    circom_to_rust_migration_map.md
    testing_plan.md
```

## Core Design

`proof-core` owns all AMACI business logic:

- typed `ProverInput` and `PublicOutput`;
- public input hash reconstruction;
- BN254 field compatibility;
- Poseidon and SHA256 field hashing compatibility;
- BabyJubJub, EdDSA Poseidon, ECDH, and ElGamal-related logic;
- 5-ary Merkle path checks;
- state transition, deactivate, add-new-key, and tally checks.

The zkVM guest crates only do:

```text
read ProverInput -> execute proof-core -> commit PublicOutput
```

This keeps the RISC Zero and SP1 adapters thin and avoids duplicating circuit logic per zkVM.

## RISC Zero

Install the RISC Zero toolchain:

```bash
rustup toolchain install 1.90.0 --profile minimal --component rustfmt
cargo install rzup --version 0.5.1 --locked
rzup install rust
rzup install cpp
```

Generate a real RISC Zero receipt:

```bash
mkdir -p proofs

RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-risc0-host -- prove process-messages-2-1-5 \
    --receipt proofs/process-messages-2-1-5.receipt.bin \
    --public proofs/process-messages-2-1-5.public.json
```

Verify the saved receipt without proving again:

```bash
RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-risc0-host -- verify \
    --receipt proofs/process-messages-2-1-5.receipt.bin \
    --public proofs/process-messages-2-1-5.verified-public.json
```

Expected verifier output includes:

```text
receipt verify ok
```

Compare public outputs:

```bash
cmp -s proofs/process-messages-2-1-5.public.json \
  proofs/process-messages-2-1-5.verified-public.json && echo "public output match"
```

## SP1

Install the SP1 toolchain:

```bash
curl -L https://sp1up.succinct.xyz | bash
export PATH="$HOME/.sp1/bin:$PATH"
~/.sp1/bin/sp1up

cargo prove --version
RUSTUP_TOOLCHAIN=succinct cargo --version
```

If the program build fails with missing RISC-V C tooling:

```bash
~/.sp1/bin/sp1up --c-toolchain
```

Generate an SP1 proof:

```bash
mkdir -p sp1-proofs

CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-sp1-host -- prove process-messages-2-1-5 \
    --proof sp1-proofs/process-messages-2-1-5.sp1-proof.bin \
    --public sp1-proofs/process-messages-2-1-5.public.json
```

Verify the saved proof without proving again:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-sp1-host -- verify \
    --proof sp1-proofs/process-messages-2-1-5.sp1-proof.bin \
    --public sp1-proofs/process-messages-2-1-5.verified-public.json
```

Expected verifier output includes:

```text
proof verify ok
```

Compare public outputs:

```bash
cmp -s sp1-proofs/process-messages-2-1-5.public.json \
  sp1-proofs/process-messages-2-1-5.verified-public.json && echo "public output match"
```

## Tests

Run the core tests:

```bash
cargo test -p amaci-proof-core
```

Build/check the current zkVM adapters:

```bash
cargo check -p amaci-proof-risc0-host
cargo check -p amaci-proof-sp1-host
```

SP1 host builds require the Succinct `succinct` Rust toolchain installed by `sp1up`.

## Important Limits

- The current guest logic uses `num-bigint`, arkworks, Poseidon, and BabyJubJub-compatible Rust implementations. It prioritizes Circom equivalence and auditability over zkVM performance.
- The RISC Zero and SP1 proof CLIs currently expose built-in inputs for `process-messages-2-1-5` and `tally-votes-2-1-1`.
- Local verifier closure is implemented for both zkVMs, but this is not yet a CosmWasm/on-chain verifier integration.
- SP1 currently uses core proof mode. Compressed, Groth16, and Plonk modes are intentionally deferred until the chain-facing verifier target is selected.

## Documentation

- [RISC Zero proving runbook](docs/risc0_proving_runbook.md)
- [SP1 proving runbook](docs/sp1_proving_runbook.md)
- [Circom to Rust migration map](docs/circom_to_rust_migration_map.md)
- [RISC Zero and SP1 adapter boundary](docs/risc0_sp1_adapter_boundary.md)
- [Testing plan](docs/testing_plan.md)
