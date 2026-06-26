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
