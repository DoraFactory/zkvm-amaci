# RISC Zero Proving Runbook

This runbook uses the native protocol backend only.

## Setup

```bash
curl -L https://risczero.com/install | bash
rzup install
```

## Prove In Background

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

Watch:

```bash
tail -f $(ls -t logs/risc0-proof-*.log | head -1)
```

## Verify

```bash
RISC0_DEV_MODE=0 CARGO_TARGET_DIR=/tmp/zkvm-amaci-risc0-target \
  cargo --config configs/cargo-risc0-native-patches.toml run --release \
    -p amaci-proof-risc0-host -- \
    verify \
    --receipt proofs/process-messages-native-2-1-5-full.risc0.receipt.bin \
    --public proofs/process-messages-native-2-1-5-full.risc0.verified-public.json
```

Check public output:

```bash
cmp -s proofs/process-messages-native-2-1-5-full.risc0.public.json \
  proofs/process-messages-native-2-1-5-full.risc0.verified-public.json \
  && echo "risc0 public output match"
```

The run is successful when verify prints `receipt verify ok` and the public
output compare matches.
