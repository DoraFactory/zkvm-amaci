# CosmWasm SP1 Groth16 Verifier

This repository includes a minimal CosmWasm verifier PoC in
`crates/cosmwasm-sp1-verifier`.

The contract verifies SP1 Groth16 wrapper proofs using:

- raw Groth16 proof bytes from `SP1ProofWithPublicValues::bytes()`;
- raw SP1 public values bytes from `proof.public_values.as_slice()`;
- SP1 program vkey hash from `pk.verifying_key().bytes32()`;
- SP1's bundled `GROTH16_VK_BYTES` for version `6.3.0`.

## Build

```bash
rustup target add wasm32-unknown-unknown
cargo build --profile contract -p amaci-cosmwasm-sp1-verifier --target wasm32-unknown-unknown
ls -lh target/wasm32-unknown-unknown/contract/amaci_cosmwasm_sp1_verifier.wasm
```

The `contract` profile strips symbols and optimizes for size. The current PoC
builds as a deployable wasm artifact, but target-chain gas must still be
measured.

## Generate SP1 Groth16 Artifacts

```bash
nohup bash scripts/run_bench.sh sp1-groth16 process-messages-native-2-1-5-full \
  > logs/bench-sp1-groth16-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

The verifier inputs are:

```text
proof        = sp1-proofs/process-messages-native-2-1-5-full.sp1-groth16-proof.bytes
publicValues = sp1-proofs/process-messages-native-2-1-5-full.sp1-groth16.public.bin
vkeyHash     = contents of sp1-proofs/process-messages-native-2-1-5-full.sp1-groth16.vkey.txt
```

## Contract Message

```json
{
  "verify_groth16": {
    "proof": "<base64 proof bytes>",
    "public_values": "<base64 public values bytes>",
    "vkey_hash": "0x..."
  }
}
```

## Notes

- The verifier crate uses `sp1-verifier = 6.3.0` with default features disabled.
- A custom `getrandom` backend is registered for wasm that always fails. The
  verifier path should not require randomness; if it does, verification fails
  rather than importing JS random APIs.
- The first integration target is proof correctness. Gas and upload size must
  be measured on the target Cosmos chain before treating this as production
  ready.
