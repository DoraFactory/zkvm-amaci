# SP1 Proving Runbook

This runbook covers the SP1 proving path for the Rust AMACI core.

## Current Status

Implemented under `zkvm-amaci`:

- `amaci-proof-sp1-program`: SP1 guest program that reads `ProverInput`, executes `execute_proof_logic`, and commits `PublicOutput`.
- `amaci-proof-sp1-host`: host runner that builds the SP1 ELF, proves a built-in AMACI input, verifies the generated proof, saves/loads proof artifacts, decodes public values, and checks them against native `proof-core` output.

The host currently supports:

- `process-messages-2-1-5`
- `tally-votes-2-1-1`

The remaining AMACI circuits should be wired after the shared built-in input layer is expanded.

## Machine Setup

SP1 requires the Succinct toolchain in addition to the normal Rust toolchain:

```bash
curl -L https://sp1up.succinct.xyz | bash
~/.sp1/bin/sp1up
```

Verify the installation:

```bash
cargo prove --version
RUSTUP_TOOLCHAIN=succinct cargo --version
```

If the program build fails with missing RISC-V C tools, reinstall with:

```bash
~/.sp1/bin/sp1up --c-toolchain
```

## Fast Local Proof

From `zkvm-amaci/`:

```bash
mkdir -p sp1-proofs

CARGO_TARGET_DIR=/tmp/zkvm-amaci-target \
  cargo run --release -p amaci-proof-sp1-host -- prove process-messages-2-1-5 \
    --proof sp1-proofs/process-messages-2-1-5.sp1-proof.bin \
    --public sp1-proofs/process-messages-2-1-5.public.json \
  2>&1 | tee sp1-proof-$(date +%Y%m%d-%H%M%S).log
```

The SP1 host currently produces a core proof, which is the fastest local proof mode and is enough for local verifier closure.

## Independent Local Verify

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
proof=sp1-proofs/process-messages-2-1-5.sp1-proof.bin
vkey_hash=0x...
{
  "ProcessMessages": {
    ...
  }
}
```

Then compare prover and verifier public output:

```bash
cmp -s sp1-proofs/process-messages-2-1-5.public.json \
  sp1-proofs/process-messages-2-1-5.verified-public.json && echo "public output match"
```

## Notes

- SP1 `setup` is run by both prover and verifier to derive the verifying key from the embedded ELF. The verifier command does not rerun proving.
- The SP1 guest uses the same BigUint-heavy `proof-core` implementation as RISC Zero. It is intended first for semantic and proof-pipeline closure, not performance.
- Compressed, Groth16, and Plonk SP1 proof modes are not enabled in this pass. They should be added later when deciding the chain-facing verifier target.
