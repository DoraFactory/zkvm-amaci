# RISC Zero Proving Runbook

This runbook covers the current RISC Zero proving path for the Rust AMACI core.

## Current Status

Implemented under `zkvm-amaci`:

- `amaci-proof-risc0-guest`: RISC Zero guest that reads `ProverInput`, executes `execute_proof_logic`, and commits `PublicOutput`.
- `amaci-proof-risc0-methods`: `risc0-build` methods crate that builds and embeds the guest ELF/image ID.
- `amaci-proof-risc0-host`: host runner that builds a small valid AMACI input, proves it, verifies the receipt, decodes the journal, checks it against native `proof-core` output, and can save/load receipt artifacts for an independent local verifier command.
- local `rust-toolchain.toml` pinned to Rust `1.90.0`, required by current RISC Zero dependency resolution.
- local `patches/blake` shim to avoid the legacy native `blake` crate failing on the RISC Zero guest target.

Verified locally:

- `cargo build -p amaci-proof-risc0-host` succeeds.
- `RISC0_DEV_MODE=1 cargo run -p amaci-proof-risc0-host -- process-messages-2-1-5` succeeds.
- `RISC0_DEV_MODE=1 cargo run -p amaci-proof-risc0-host -- prove process-messages-2-1-5 --receipt /tmp/process.receipt.bin --public /tmp/process.public.json` succeeds.
- `RISC0_DEV_MODE=1 cargo run -p amaci-proof-risc0-host -- verify --receipt /tmp/process.receipt.bin` succeeds.
- Real proving for `process-messages-2-1-5` starts and keeps computing, but was stopped on a low-spec machine after about 1 hour 49 minutes.

## Machine Setup

From `zkvm-amaci/`:

```bash
rustup toolchain install 1.90.0 --profile minimal --component rustfmt
cargo install rzup --version 0.5.1 --locked
rzup install rust
rzup install cpp
```

The RISC Zero guest build uses the RISC Zero toolchains installed by `rzup`, not the normal host Rust toolchain.

## Fast Pipeline Check

Use dev mode first to verify host/guest IO, journal decode, and receipt API wiring:

```bash
cd /Users/bun/DoraFactory/maci/zkvm-amaci
RISC0_DEV_MODE=1 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run -p amaci-proof-risc0-host -- process-messages-2-1-5
```

Expected behavior:

- prints RISC Zero dev-mode warnings;
- prints `circuit=process-messages-2-1-5`;
- prints the guest `image_id`;
- prints a `PublicOutput::ProcessMessages` JSON journal.

Dev mode does not produce a secure proof.

To test receipt artifact IO and the independent verifier CLI in dev mode:

```bash
RISC0_DEV_MODE=1 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run -p amaci-proof-risc0-host -- prove process-messages-2-1-5 \
    --receipt proofs/process-messages-2-1-5.receipt.bin \
    --public proofs/process-messages-2-1-5.public.json

RISC0_DEV_MODE=1 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run -p amaci-proof-risc0-host -- verify \
    --receipt proofs/process-messages-2-1-5.receipt.bin \
    --public proofs/process-messages-2-1-5.verified-public.json
```

The verifier command does not run the prover. It only deserializes the receipt, verifies it against the embedded RISC Zero image ID, decodes the journal, and prints the public output.

## Real Local Proof

Run with dev mode disabled:

```bash
cd /Users/bun/DoraFactory/maci/zkvm-amaci
RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-risc0-host -- process-messages-2-1-5
```

The first run compiles release dependencies and the guest ELF before proving. Subsequent runs reuse the target cache.

To save a full RISC Zero receipt artifact and public output:

```bash
RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-risc0-host -- prove process-messages-2-1-5 \
    --receipt proofs/process-messages-2-1-5.receipt.bin \
    --public proofs/process-messages-2-1-5.public.json \
  2>&1 | tee proof-$(date +%Y%m%d-%H%M%S).log
```

Then verify the saved receipt without proving again:

```bash
RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-risc0-host -- verify \
    --receipt proofs/process-messages-2-1-5.receipt.bin \
    --public proofs/process-messages-2-1-5.verified-public.json
```

Expected verifier output includes:

```text
receipt verify ok
receipt=proofs/process-messages-2-1-5.receipt.bin
image_id=[...]
{
  "ProcessMessages": {
    ...
  }
}
```

## Available Host Inputs

The host currently supports:

- `process-messages-2-1-5`
- `tally-votes-2-1-1`

Example:

```bash
RISC0_DEV_MODE=1 CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run -p amaci-proof-risc0-host -- tally-votes-2-1-1
```

## Notes

- The current guest uses the same BigUint-heavy `proof-core` implementation used by ordinary Rust tests. This is good for semantic confidence, but expensive for zkVM proving.
- The local `blake` patch is only to make transitive crypto dependencies compile for the guest target. The current guest proving path does not rely on Blake key derivation for the built-in empty-message proof input.
- If real proving is too slow on a small machine, move the same workspace to a larger CPU/RAM machine and rerun the real proof command above.
