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
- `process-messages-native-1-1` when built with `--features zkvm-native-crypto`

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
    zkvm_optimization_notes.md
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

## Crypto Backends

The default build is Circom-compatible and keeps the original Poseidon-based
commitments and Merkle hashes.

The `zkvm-native-crypto` feature keeps the same AMACI protocol flow but switches
protocol-level commitments, Merkle hashes, message chains, and public input
hashes to domain-separated SHA-256 field hashes. This mode is intended for zkVM
performance work and is not byte-compatible with the Circom fixtures.

In native mode, public keys are stored as full 32-byte `[Ed25519 verifying key,
X25519 public key]` values. Command signatures are Ed25519 signatures stored
across `sig_r8[0]`, `sig_r8[1]`, and `sig_s` as 22/21/21-byte chunks. Shared
keys are derived with X25519, and message payload encryption/decryption uses a
SHA-256 XOR keystream helper. Non-empty native witnesses must be generated with
the native helpers, not with the Circom Poseidon/BabyJubJub tooling.

RISC Zero and SP1 use different patched crypto crate sources, so the workspace
does not globally patch `sha2` or `curve25519-dalek`. Use the backend-specific
Cargo config files when you want guest builds to route SHA-256/Curve25519
through zkVM precompiles:

```bash
cargo --config configs/cargo-risc0-native-patches.toml ...
cargo --config configs/cargo-sp1-native-patches.toml ...
```

Check the native backend:

```bash
cargo test -p amaci-proof-core --features zkvm-native-crypto
cargo check -p amaci-proof-risc0-host --features zkvm-native-crypto
cargo check -p amaci-proof-sp1-host --features zkvm-native-crypto

RISC0_DEV_MODE=1 CARGO_TARGET_DIR=/tmp/zkvm-amaci-native-target \
  cargo run -p amaci-proof-risc0-host --features zkvm-native-crypto -- \
    process-messages-native-2-1-5
```

Profile the native core logic without proving:

```bash
cargo run --release -p amaci-proof-core --features zkvm-native-crypto \
  --bin native_profile -- process-messages-native-2-1-5 --iters 100
```

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

Generate a RISC Zero receipt with the zkVM-native crypto backend:

```bash
mkdir -p proofs

RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-native-target \
  cargo --config configs/cargo-risc0-native-patches.toml run --release \
    -p amaci-proof-risc0-host --features zkvm-native-crypto -- \
    prove process-messages-native-2-1-5 \
    --receipt proofs/process-messages-native-2-1-5.receipt.bin \
    --public proofs/process-messages-native-2-1-5.public.json
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

Generate an SP1 proof with the zkVM-native crypto backend:

```bash
mkdir -p sp1-proofs

CARGO_TARGET_DIR=/tmp/zkvm-amaci-native-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host --features zkvm-native-crypto -- \
    prove process-messages-native-2-1-5 \
    --proof sp1-proofs/process-messages-native-2-1-5.sp1-proof.bin \
    --public sp1-proofs/process-messages-native-2-1-5.public.json
```

Execute the SP1 guest without proving and print the execution report:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-native-target \
  cargo --config configs/cargo-sp1-native-patches.toml run \
    -p amaci-proof-sp1-host --features zkvm-native-crypto -- \
    execute process-messages-native-2-1-5 \
    --public sp1-proofs/process-messages-native-2-1-5.execute-public.json
```

Expected execute output includes:

```text
execute ok
instructions=...
gas=...
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

- The default Circom-compatible guest logic still uses `num-bigint`, arkworks, Poseidon, and BabyJubJub-compatible Rust implementations, with low-risk zkVM-friendly allocation and constant-cache optimizations applied.
- The native backend replaces protocol hashes, command signatures, key agreement, and message encryption for the currently wired native sample path. The Rust representation is still `BigUint`, and native public-key/message words may use the full 256-bit byte range instead of staying below the BN254 scalar field.
- `zkvm-native-crypto` changes protocol hash outputs and therefore changes image IDs, public outputs, and proof artifacts. Do not compare native-mode outputs against Circom golden fixtures.
- The RISC Zero and SP1 proof CLIs currently expose built-in inputs for `process-messages-2-1-5`, `tally-votes-2-1-1`, and native-mode `process-messages-native-1-1` / `process-messages-native-2-1-5`.
- Local verifier closure is implemented for both zkVMs, but this is not yet a CosmWasm/on-chain verifier integration.
- SP1 currently uses core proof mode. Compressed, Groth16, and Plonk modes are intentionally deferred until the chain-facing verifier target is selected.

## Documentation

- [RISC Zero proving runbook](docs/risc0_proving_runbook.md)
- [SP1 proving runbook](docs/sp1_proving_runbook.md)
- [Circom to Rust migration map](docs/circom_to_rust_migration_map.md)
- [RISC Zero and SP1 adapter boundary](docs/risc0_sp1_adapter_boundary.md)
- [zkVM optimization notes](docs/zkvm_optimization_notes.md)
- [Testing plan](docs/testing_plan.md)
