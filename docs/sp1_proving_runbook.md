# SP1 Proving Runbook

This runbook uses the native protocol backend only.

## Setup

```bash
curl -L https://sp1.succinct.xyz | bash
sp1up
```

## Prove In Background

Preferred command with metrics:

```bash
cd ~/zkvm-amaci
git pull --ff-only origin main
mkdir -p logs metrics sp1-proofs

nohup bash scripts/run_bench.sh sp1 process-messages-native-2-1-5-full \
  > logs/bench-sp1-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Manual command:

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

Watch:

```bash
tail -f $(ls -t logs/sp1-*.log logs/sp1-proof-*.log 2>/dev/null | head -1)
```

## Verify

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host -- \
    verify \
    --proof sp1-proofs/process-messages-native-2-1-5-full.sp1-proof.bin \
    --public sp1-proofs/process-messages-native-2-1-5-full.sp1.verified-public.json
```

Check public output:

```bash
cmp -s sp1-proofs/process-messages-native-2-1-5-full.sp1.public.json \
  sp1-proofs/process-messages-native-2-1-5-full.sp1.verified-public.json \
  && echo "sp1 public output match"
```

The run is successful when verify prints `proof verify ok` and the public
output compare matches. Record `input_bytes`, `public_bytes`, `proof_bytes`,
and `Maximum resident set size` from the matching metrics and time files under
`metrics/`.

## Execute Only

Preferred command with metrics:

```bash
nohup bash scripts/run_bench.sh sp1-execute process-messages-native-2-1-5-full \
  > logs/bench-sp1-execute-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Manual command:

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host -- \
    execute process-messages-native-2-1-5-full \
    --public sp1-proofs/process-messages-native-2-1-5-full.sp1.execute-public.json
```

## Compressed STARK Proof

Generate a compressed STARK proof and verify the raw compressed artifacts:

```bash
cd ~/zkvm-amaci
git pull --ff-only origin main
mkdir -p logs metrics sp1-proofs

nohup bash scripts/run_bench.sh sp1-compressed process-messages-native-2-1-5-full \
  > logs/bench-sp1-compressed-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Watch:

```bash
tail -f $(ls -t logs/sp1-compressed-*.log 2>/dev/null | head -1)
```

The run is successful when the log contains `compressed proof verify ok` and
`sp1 compressed public output match`.

Artifacts:

- `sp1-proofs/*.sp1-compressed-proof.bin`: full SDK proof with public values.
- `sp1-proofs/*.sp1-compressed-proof.bytes`: bincode-encoded
  `SP1Proof::Compressed`, accepted by `SP1CompressedVerifierRaw`.
- `sp1-proofs/*.sp1-compressed.public.bin`: raw public values bytes committed by
  the guest.
- `sp1-proofs/*.sp1-compressed.vkey.bin`: bincode-encoded SP1 program verifying
  key digest.

This is the end-to-end PQC candidate path. It does not use the BN254
Groth16/PLONK wrapper.

### Real Five-Signup Round

Generate all five real AMACI round compressed proofs on the high-performance
machine:

```bash
cd ~/zkvm-amaci
git pull --ff-only origin main
mkdir -p logs metrics sp1-proofs

nohup bash scripts/run_five_signup_sp1_compressed.sh \
  > logs/five-signup-sp1-compressed-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Watch:

```bash
tail -f $(ls -t logs/five-signup-sp1-compressed-*.out logs/sp1-compressed-five-signup-*.log 2>/dev/null | head -1)
```

The script runs these circuits:

```text
five-signup-process-deactivate
five-signup-add-new-key
five-signup-process-messages-full
five-signup-tally-0
five-signup-tally-1
```

For every circuit, success means the corresponding `logs/sp1-compressed-*.log`
contains both `compressed proof verify ok` and
`sp1 compressed public output match`.

The script also writes CosmWasm execute messages:

```text
sp1-proofs/five-signup-*.verify-compressed.msg.json
```

Copy those files back to the local machine, then use
`fixtures/round-e2e.five-signup.example.json` with
`scripts/run_cosmwasm_round_e2e.mjs` to measure the real on-chain round cost.

### Fifteen-Signup Aggregation Benchmark

The larger fixture keeps the `2-1-1-5` per-proof capacity and executes a full
round with:

- 15 initial signups;
- two deactivated old keys;
- one replacement key appended by `AddNewKey`, for 16 final state leaves;
- 15 vote messages split across three `processMessages` batches;
- 16 state leaves split across four `tally` batches;
- three process-message child proofs aggregated into one proof;
- four tally child proofs aggregated into one proof.

The 15 messages contain 13 valid votes and two invalid old-key votes. The
expected raw tally is `[3, 6, 6, 8, 15]`.

The concrete vote plan is deterministic:

- old state 13 submits option 1 with weight 2 after deactivation; it is invalid;
- old state 14 submits option 2 with weight 3 after deactivation and key
  replacement; it is invalid;
- states 0 through 11 each submit one valid vote, choosing `stateIndex % 5`
  and weight `optionIndex + 1`;
- replacement state 15 submits option 4 with weight 5;
- state 12 submits no message.

Run the complete child proving and aggregation suite in the background on the
proving machine:

```bash
mkdir -p logs metrics sp1-proofs

nohup env \
  SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  scripts/run_fifteen_signup_sp1_aggregation.sh \
  > logs/fifteen-signup-aggregation-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

The script proves sequentially. Follow it with:

```bash
tail -f $(ls -t logs/fifteen-signup-aggregation-*.out | head -1)

tail -f $(ls -t \
  logs/sp1-compressed-fifteen-signup-*.log \
  logs/sp1-aggregate-*.log 2>/dev/null | head -1)
```

Completion checks:

```bash
pgrep -af 'amaci-proof-sp1|sp1-prover'

grep -n 'aggregate compressed verify ok' \
  $(ls -t logs/sp1-aggregate-process-messages-*.log | head -1)

grep -n 'aggregate compressed verify ok' \
  $(ls -t logs/sp1-aggregate-tally-*.log | head -1)

ls -lh sp1-proofs/fifteen-signup-aggregate-artifacts.tar.gz
```

The archive includes all nine non-aggregate child execute messages, both
aggregate proof triplets, and both aggregate execute messages. The same
proving run therefore supports aggregate and non-aggregate chain comparisons.
Copy it to the local machine and extract it from the repository root:

```bash
tar -xzf sp1-proofs/fifteen-signup-aggregate-artifacts.tar.gz
```

The archive already contains the two aggregate CosmWasm messages. They can be
rebuilt from the raw artifacts when needed:

```bash
scripts/make_cosmwasm_sp1_aggregate_msg.sh process-messages \
  sp1-proofs/fifteen-signup-process-messages.aggregate \
  > sp1-proofs/fifteen-signup-process-messages.aggregate.verify-compressed-aggregate.msg.json

scripts/make_cosmwasm_sp1_aggregate_msg.sh tally \
  sp1-proofs/fifteen-signup-tally.aggregate \
  > sp1-proofs/fifteen-signup-tally.aggregate.verify-compressed-aggregate.msg.json
```

The local aggregate E2E manifest is
`fixtures/round-e2e.fifteen-signup.aggregate.example.json`. The matching
non-aggregate manifest is `fixtures/round-e2e.fifteen-signup.example.json`.

## Groth16 Wrapper

Generate a Groth16-wrapped proof and verify the raw on-chain artifacts:

```bash
cd ~/zkvm-amaci
git pull --ff-only origin main
mkdir -p logs metrics sp1-proofs

nohup bash scripts/run_bench.sh sp1-groth16 process-messages-native-2-1-5-full \
  > logs/bench-sp1-groth16-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Watch:

```bash
tail -f $(ls -t logs/sp1-groth16-*.log 2>/dev/null | head -1)
```

The run is successful when the log contains `groth16 proof verify ok` and
`sp1 groth16 public output match`.

Artifacts:

- `sp1-proofs/*.sp1-groth16-proof.bin`: full SDK proof with public values.
- `sp1-proofs/*.sp1-groth16-proof.bytes`: raw proof bytes accepted by SP1
  on-chain/CosmWasm verifiers.
- `sp1-proofs/*.sp1-groth16.public.bin`: raw public values bytes committed by
  the guest.
- `sp1-proofs/*.sp1-groth16.vkey.txt`: SP1 program verifying key hash.

The CosmWasm verifier consumes the raw proof bytes, raw public values bytes,
and vkey hash.
