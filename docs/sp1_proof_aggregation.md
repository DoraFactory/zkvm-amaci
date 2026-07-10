# SP1 Proof Aggregation

This branch adds the first SP1 recursive aggregation paths for repeated AMACI
round stages. The current implementation aggregates:

- process-message child proofs;
- tally child proofs.

## What Is Aggregated

The aggregate proof verifies existing SP1 compressed child proofs inside a new
SP1 guest. It does not replace the child circuit semantics:

- every child proof is still produced by `amaci-proof-sp1-program`;
- the aggregate guest calls SP1 proof verification for each child proof;
- the aggregate guest checks the child public outputs form a valid stage chain;
- the aggregate public output only commits to the linked stage range.

For process-message aggregation, the public-output checks are:

- child outputs must all be `ProcessMessages`;
- `packed_vals`, `coord_pub_key_hash`, `deactivate_commitment`, and
  `expected_poll_id` must stay constant across children;
- each child `batch_start_hash` must equal the previous child
  `batch_end_hash`;
- each child `current_state_commitment` must equal the previous child
  `new_state_commitment`;
- the aggregate output includes the initial/final message hash, initial/final
  state commitment, shared parameters, and a SHA-256 hash over all child public
  outputs.

For tally aggregation, the public-output checks are:

- child outputs must all be `TallyVotes`;
- `batch_num` must be consecutive;
- all children must use the same `state_commitment`;
- each child `current_tally_commitment` must equal the previous child
  `new_tally_commitment`;
- the aggregate output includes the first batch, last batch, initial tally
  commitment, final tally commitment, and a SHA-256 hash over all child public
  outputs.

## Code Layout

- `crates/proof-core/src/aggregate.rs`
  - aggregate public-output codec;
  - process-message and tally linkage checks;
  - unit tests for valid and invalid child chains.
- `crates/proof-sp1-aggregate-program/src/main.rs`
  - SP1 guest that verifies child proofs and commits aggregate public output.
- `crates/proof-sp1-aggregate-host/src/main.rs`
  - host CLI that loads child compressed proofs or CosmWasm
    `verify-compressed.msg.json` files;
  - proves/verifies the aggregate compressed proof;
  - exports proof bytes, public bytes, and aggregate vkey hash.
- `scripts/run_sp1_aggregate_tally.sh`
  - reproducible high-performance-machine runner with logs and metrics.
- `scripts/run_sp1_aggregate_process_messages.sh`
  - reproducible process-message aggregate runner with logs and metrics.

## Generate Child Proofs

The aggregate runners expect existing child artifacts. Generate them with the
normal five-signup compressed suite:

```bash
nohup bash scripts/run_five_signup_sp1_compressed.sh \
  > logs/five-signup-sp1-compressed-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Required child inputs:

```text
sp1-proofs/five-signup-tally-0.verify-compressed.msg.json
sp1-proofs/five-signup-tally-1.verify-compressed.msg.json
sp1-proofs/five-signup-process-messages-full.verify-compressed.msg.json
```

## Prove Aggregate Process Messages

Run on the high-performance machine:

```bash
nohup env CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  scripts/run_sp1_aggregate_process_messages.sh \
  > logs/sp1-aggregate-process-messages-run-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

For larger rounds, pass every process-message child msg in order:

```bash
nohup env CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  scripts/run_sp1_aggregate_process_messages.sh \
    sp1-proofs/process-messages-0.verify-compressed.msg.json \
    sp1-proofs/process-messages-1.verify-compressed.msg.json \
    sp1-proofs/process-messages-2.verify-compressed.msg.json \
  > logs/sp1-aggregate-process-messages-run-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Track progress:

```bash
tail -f $(ls -t logs/sp1-aggregate-process-messages-*.log logs/sp1-aggregate-process-messages-run-*.out 2>/dev/null | head -1)
```

Outputs:

```text
sp1-proofs/five-signup-process-messages.aggregate.sp1-compressed-proof.bin
sp1-proofs/five-signup-process-messages.aggregate.sp1-compressed-proof.bytes
sp1-proofs/five-signup-process-messages.aggregate.public.json
sp1-proofs/five-signup-process-messages.aggregate.public.bin
sp1-proofs/five-signup-process-messages.aggregate.vkey.bin
metrics/sp1-aggregate-process-messages-*.metrics.txt
metrics/sp1-aggregate-process-messages-*.time.txt
```

Success markers:

```bash
grep -n "aggregate compressed verify ok" $(ls -t logs/sp1-aggregate-process-messages-*.log | head -1)
cat $(ls -t metrics/sp1-aggregate-process-messages-*.metrics.txt | head -1)
```

## Prove Aggregate Tally

Run on the high-performance machine:

```bash
nohup env CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  scripts/run_sp1_aggregate_tally.sh \
  > logs/sp1-aggregate-tally-run-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Track progress:

```bash
tail -f $(ls -t logs/sp1-aggregate-tally-*.log logs/sp1-aggregate-tally-run-*.out 2>/dev/null | head -1)
```

Outputs:

```text
sp1-proofs/five-signup-tally.aggregate.sp1-compressed-proof.bin
sp1-proofs/five-signup-tally.aggregate.sp1-compressed-proof.bytes
sp1-proofs/five-signup-tally.aggregate.public.json
sp1-proofs/five-signup-tally.aggregate.public.bin
sp1-proofs/five-signup-tally.aggregate.vkey.bin
metrics/sp1-aggregate-tally-*.metrics.txt
metrics/sp1-aggregate-tally-*.time.txt
```

Success markers:

```bash
grep -n "aggregate compressed verify ok" $(ls -t logs/sp1-aggregate-tally-*.log | head -1)
cat $(ls -t metrics/sp1-aggregate-tally-*.metrics.txt | head -1)
```

## Verify Aggregate Tally

Verify from the raw compressed artifacts:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
  -p amaci-proof-sp1-aggregate-host -- \
  verify-compressed \
  --proof-bytes sp1-proofs/five-signup-tally.aggregate.sp1-compressed-proof.bytes \
  --public-bytes sp1-proofs/five-signup-tally.aggregate.public.bin \
  --vkey sp1-proofs/five-signup-tally.aggregate.vkey.bin \
  --public sp1-proofs/five-signup-tally.aggregate.verified-public.json
```

Success marker:

```text
aggregate compressed proof verify ok
```

For process-message aggregate verification, use the same command shape with
the process-message aggregate artifact names:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
  -p amaci-proof-sp1-aggregate-host -- \
  verify-compressed \
  --proof-bytes sp1-proofs/five-signup-process-messages.aggregate.sp1-compressed-proof.bytes \
  --public-bytes sp1-proofs/five-signup-process-messages.aggregate.public.bin \
  --vkey sp1-proofs/five-signup-process-messages.aggregate.vkey.bin \
  --public sp1-proofs/five-signup-process-messages.aggregate.verified-public.json
```

## Hierarchical Successor

The flat aggregate path remains useful as a comparison baseline. Large rounds
should use the fixed-fan-in recursive scheduler in
`docs/sp1_tree_aggregation.md`: it groups at most five proofs per node, repeats
the grouping across levels, and combines both stage roots with
`processDeactivate` and `addNewKey` into one final proof for CosmWasm.
