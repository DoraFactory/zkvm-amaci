# zkvm-amaci

Native zkVM implementation of the AMACI proof logic for RISC Zero and SP1.

The codebase keeps one protocol backend only: SHA-256 based commitments, Ed25519
command signatures, X25519 key agreement, and byte-oriented message encryption.
Both zkVM hosts use the same `proof-core` execution logic and verify their
public output against the host-side result before writing proof artifacts.

The witness layer is fixed-width where the protocol shape is fixed: field words
are `U256`, public values are `[u8; 32]` digests, messages are `[Field; 10]`,
state leaves are `[Field; 10]`, vote rows are `[Field; 5]` for the current
`vote_option_tree_depth = 1` target, and quin Merkle siblings are `[Field; 4]`.
RISC Zero and SP1 private inputs and public journal values use the shared
`proof-core` compact byte codec instead of guest-side serde decoding/encoding
of the full Rust input and output graph.

## Crates

```text
crates/
  proof-core/            Shared protocol logic, native fixtures, public outputs.
  proof-risc0-guest/     RISC Zero guest entrypoint.
  proof-risc0-methods/   RISC Zero method build wrapper and image ID export.
  proof-risc0-host/      RISC Zero prove/verify CLI.
  proof-sp1-program/     SP1 guest program entrypoint.
  proof-sp1-host/        SP1 prove/execute/verify CLI.
configs/
  cargo-risc0-native-patches.toml
  cargo-sp1-native-patches.toml
```

## Built-In Inputs

The CLIs accept these native fixtures:

- `process-messages-native-1-1`
- `process-messages-native-2-1-5`
- `process-messages-native-2-1-5-full`
- `tally-votes-native-2-1-1`
- `process-deactivate-native-2-5`
- `add-new-key-native-2`

The default circuit for both RISC Zero and SP1 hosts is
`process-messages-native-2-1-5-full`.

## Local Checks

```bash
cargo test -p amaci-proof-core
cargo check -p amaci-proof-risc0-host
cargo check -p amaci-proof-sp1-host
```

Profile the shared protocol logic without proving:

```bash
cargo run --release -p amaci-proof-core --bin native_profile -- \
  process-messages-native-2-1-5-full --iters 100
```

## Bench / Metrics Runner

For high-performance machines, use the bench runner so logs, timing, memory,
artifact sizes, and public-output comparisons are captured consistently:

```bash
cd ~/zkvm-amaci
git pull --ff-only origin main
chmod +x scripts/run_bench.sh
mkdir -p logs metrics proofs sp1-proofs

nohup bash scripts/run_bench.sh risc0 process-messages-native-2-1-5-full \
  > logs/bench-risc0-$(date +%Y%m%d-%H%M%S).out 2>&1 &

nohup bash scripts/run_bench.sh sp1 process-messages-native-2-1-5-full \
  > logs/bench-sp1-$(date +%Y%m%d-%H%M%S).out 2>&1 &

nohup bash scripts/run_bench.sh sp1-execute process-messages-native-2-1-5-full \
  > logs/bench-sp1-execute-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Watch the latest backend log:

```bash
tail -f $(ls -t logs/risc0-process-messages-native-2-1-5-full-*.log | head -1)
tail -f $(ls -t logs/sp1-process-messages-native-2-1-5-full-*.log | head -1)
```

After completion, inspect:

```bash
ls -lt metrics/*.metrics.txt metrics/*.time.txt | head
cat $(ls -t metrics/risc0-process-messages-native-2-1-5-full-*.metrics.txt | head -1)
cat $(ls -t metrics/sp1-process-messages-native-2-1-5-full-*.metrics.txt | head -1)
```

Key fields to record are `input_bytes`, `public_bytes`, proof/receipt size,
`Maximum resident set size` from the matching `.time.txt`, and the verify
compare line (`risc0 public output match` or `sp1 public output match`).

## RISC Zero

Install:

```bash
curl -L https://risczero.com/install | bash
rzup install
```

Run a real proof in the background:

```bash
cd ~/zkvm-amaci
mkdir -p logs proofs

nohup env RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-risc0-target \
  cargo --config configs/cargo-risc0-native-patches.toml run --release \
    -p amaci-proof-risc0-host -- \
    prove process-messages-native-2-1-5-full \
    --receipt proofs/process-messages-native-2-1-5-full.risc0.receipt.bin \
    --public proofs/process-messages-native-2-1-5-full.risc0.public.json \
  > logs/risc0-proof-$(date +%Y%m%d-%H%M%S).log 2>&1 &
```

Verify the receipt:

```bash
RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-risc0-target \
  cargo --config configs/cargo-risc0-native-patches.toml run --release \
    -p amaci-proof-risc0-host -- \
    verify \
    --receipt proofs/process-messages-native-2-1-5-full.risc0.receipt.bin \
    --public proofs/process-messages-native-2-1-5-full.risc0.verified-public.json

cmp -s proofs/process-messages-native-2-1-5-full.risc0.public.json \
  proofs/process-messages-native-2-1-5-full.risc0.verified-public.json \
  && echo "risc0 public output match"
```

Success criteria:

- log contains `receipt=...`;
- log contains `input_bytes=...` and `public_bytes=...`;
- verify prints `receipt verify ok`;
- public JSON compare prints `risc0 public output match`.

## SP1

Install:

```bash
curl -L https://sp1.succinct.xyz | bash
sp1up
```

Run a real proof in the background:

```bash
cd ~/zkvm-amaci
mkdir -p logs sp1-proofs

nohup env CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host -- \
    prove process-messages-native-2-1-5-full \
    --proof sp1-proofs/process-messages-native-2-1-5-full.sp1-proof.bin \
    --public sp1-proofs/process-messages-native-2-1-5-full.sp1.public.json \
  > logs/sp1-proof-$(date +%Y%m%d-%H%M%S).log 2>&1 &
```

Verify the proof:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host -- \
    verify \
    --proof sp1-proofs/process-messages-native-2-1-5-full.sp1-proof.bin \
    --public sp1-proofs/process-messages-native-2-1-5-full.sp1.verified-public.json

cmp -s sp1-proofs/process-messages-native-2-1-5-full.sp1.public.json \
  sp1-proofs/process-messages-native-2-1-5-full.sp1.verified-public.json \
  && echo "sp1 public output match"
```

Success criteria:

- log contains `proof=...`;
- log contains `input_bytes=...` and `public_bytes=...`;
- verify prints `proof verify ok`;
- public JSON compare prints `sp1 public output match`.

For a fast SP1 execution-only check:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host -- \
    execute process-messages-native-2-1-5-full \
    --public sp1-proofs/process-messages-native-2-1-5-full.sp1.execute-public.json
```

## Notes

- `proof-core` is the protocol source of truth for both zkVMs.
- Host CLIs always recompute expected public output locally before accepting a
  generated proof.
- Guest public output is committed as fixed bytes and decoded by the hosts from
  raw journal/public-value bytes.
- Proof artifact names intentionally include the backend (`risc0` or `sp1`) so
  receipts/proofs are not mixed.
