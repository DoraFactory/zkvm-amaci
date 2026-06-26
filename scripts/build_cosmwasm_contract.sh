#!/usr/bin/env bash
set -euo pipefail

PACKAGE="${PACKAGE:-amaci-cosmwasm-sp1-verifier}"
TOOLCHAIN="${RUST_TOOLCHAIN_NIGHTLY:-nightly}"
TARGET="${TARGET:-wasm32-unknown-unknown}"
WASM_PATH="target/${TARGET}/contract/amaci_cosmwasm_sp1_verifier.wasm"

rustup target add "${TARGET}" --toolchain "${TOOLCHAIN}" >/dev/null
rustup component add rust-src --toolchain "${TOOLCHAIN}" >/dev/null

# Vota's current wasmvm rejects bulk-memory and sign-extension instructions.
# Rebuilding std with MVP-compatible flags prevents memory.copy/memory.fill from
# entering the final contract artifact.
export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=mvp -C target-feature=-bulk-memory,-sign-ext}"

cargo +"${TOOLCHAIN}" build \
  -Z build-std=std,panic_abort \
  -Z build-std-features=panic_immediate_abort \
  --profile contract \
  -p "${PACKAGE}" \
  --target "${TARGET}"

ls -lh "${WASM_PATH}"

if command -v wasm-dis >/dev/null 2>&1 && command -v rg >/dev/null 2>&1; then
  if wasm-dis "${WASM_PATH}" | rg -q 'memory\.(copy|fill|init)|data\.drop|i(32|64)\.extend(8|16|32)_s'; then
    echo "unsupported wasm instruction found in ${WASM_PATH}" >&2
    exit 1
  fi
  echo "wasm instruction check ok"
else
  echo "skipping wasm instruction check; install binaryen and ripgrep to enable it"
fi
