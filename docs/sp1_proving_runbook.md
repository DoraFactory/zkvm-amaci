# SP1 Proving Runbook

This runbook uses the native protocol backend only.

## Setup

```bash
curl -L https://sp1.succinct.xyz | bash
sp1up
```

## Prove In Background

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
tail -f $(ls -t logs/sp1-proof-*.log | head -1)
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
output compare matches.

## Execute Only

```bash
CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  cargo --config configs/cargo-sp1-native-patches.toml run --release \
    -p amaci-proof-sp1-host -- \
    execute process-messages-native-2-1-5-full \
    --public sp1-proofs/process-messages-native-2-1-5-full.sp1.execute-public.json
```
