# CosmWasm SP1 Verifier

This repository includes a minimal CosmWasm verifier PoC in
`crates/cosmwasm-sp1-verifier`.

The contract currently exposes two verification paths:

- `verify_groth16`: compact SP1 Groth16 wrapper verification. This is useful as
  a baseline, but it is not PQC.
- `verify_compressed`: SP1 compressed STARK proof verification. This is the
  end-to-end PQC candidate path.

The Groth16 path uses:

- raw Groth16 proof bytes from `SP1ProofWithPublicValues::bytes()`;
- raw SP1 public values bytes from `proof.public_values.as_slice()`;
- SP1 program vkey hash from `pk.verifying_key().bytes32()`;
- SP1's bundled `GROTH16_VK_BYTES` for version `6.3.0`.

The compressed path uses:

- bincode-encoded `SP1Proof::Compressed`;
- raw SP1 public values bytes from `proof.public_values.as_slice()`;
- bincode-encoded SP1 program verifying key digest from
  `pk.verifying_key().hash_koalabear()`.

## Build

```bash
scripts/build_cosmwasm_contract.sh
ls -lh target/wasm32-unknown-unknown/contract/amaci_cosmwasm_sp1_verifier.wasm
```

The build script uses nightly `build-std` with:

```text
-C target-cpu=mvp -C target-feature=-bulk-memory,-sign-ext
```

This matters on Vota testnet because its current wasmvm rejects bulk-memory
instructions such as `memory.copy`.

## Vota Testnet Deploy With dorad

```bash
RPC_URL=https://vota-testnet-rpc.dorafactory.org:443
CHAIN_ID=vota-testnet
DORAD_HOME=/tmp/zkvm-amaci-dorad-home
KEY_NAME=zkvm-amaci-deployer
GAS_PRICES=10000000000peaka
WASM=target/wasm32-unknown-unknown/contract/amaci_cosmwasm_sp1_verifier.wasm

mkdir -p "$DORAD_HOME"
printf '%s\n' "$MNEMONIC" | dorad keys add "$KEY_NAME" \
  --recover --keyring-backend test --home "$DORAD_HOME"

dorad tx wasm store "$WASM" \
  --from "$KEY_NAME" --keyring-backend test --home "$DORAD_HOME" \
  --node "$RPC_URL" --chain-id "$CHAIN_ID" \
  --gas auto --gas-adjustment 1.8 --gas-prices "$GAS_PRICES" \
  --broadcast-mode sync --output json -y

dorad tx wasm instantiate <CODE_ID> '{}' \
  --from "$KEY_NAME" --keyring-backend test --home "$DORAD_HOME" \
  --node "$RPC_URL" --chain-id "$CHAIN_ID" \
  --label "zkvm-amaci-sp1-compressed-$(date +%Y%m%d-%H%M%S)" \
  --no-admin --gas auto --gas-adjustment 1.5 --gas-prices "$GAS_PRICES" \
  --broadcast-mode sync --output json -y
```

Query the deployed contract:

```bash
dorad query wasm contract-state smart <CONTRACT_ADDR> '{"verifier_info":{}}' \
  --node "$RPC_URL" --chain-id "$CHAIN_ID" --output json
```

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

## Generate SP1 Compressed Artifacts

```bash
nohup bash scripts/run_bench.sh sp1-compressed process-messages-native-2-1-5-full \
  > logs/bench-sp1-compressed-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

The compressed verifier inputs are:

```text
proof        = sp1-proofs/process-messages-native-2-1-5-full.sp1-compressed-proof.bytes
publicValues = sp1-proofs/process-messages-native-2-1-5-full.sp1-compressed.public.bin
vkeyHash     = sp1-proofs/process-messages-native-2-1-5-full.sp1-compressed.vkey.bin
```

Contract message:

```json
{
  "verify_compressed": {
    "proof": "<base64 compressed proof bytes>",
    "public_values": "<base64 public values bytes>",
    "vkey_hash": "<base64 bincode vkey digest>"
  }
}
```

Build the execute JSON from generated artifacts:

```bash
scripts/make_cosmwasm_sp1_compressed_msg.sh process-messages-native-2-1-5-full \
  > sp1-proofs/process-messages-native-2-1-5-full.verify-compressed.msg.json
```

Submit the compressed proof to a deployed contract:

```bash
dorad tx wasm execute <CONTRACT_ADDR> \
  "$(cat sp1-proofs/process-messages-native-2-1-5-full.verify-compressed.msg.json)" \
  --from "$KEY_NAME" --keyring-backend test --home "$DORAD_HOME" \
  --node "$RPC_URL" --chain-id "$CHAIN_ID" \
  --gas auto --gas-adjustment 2.0 --gas-prices "$GAS_PRICES" \
  --broadcast-mode sync --output json -y
```

## Notes

- The verifier crate uses `sp1-verifier = 6.3.0` with default features disabled.
- A custom `getrandom` backend is registered for wasm that always fails. The
  verifier path should not require randomness; if it does, verification fails
  rather than importing JS random APIs.
- The first integration target is proof correctness. Gas and upload size must
  be measured on the target Cosmos chain before treating this as production
  ready.
- `verify_compressed` is currently a one-shot verifier. If this exceeds target
  chain gas or memory limits, the next step is to split the verifier into a
  session/state-machine flow across multiple transactions.
