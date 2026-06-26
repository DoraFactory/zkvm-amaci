#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/make_cosmwasm_sp1_compressed_msg.sh [circuit]

Builds a CosmWasm execute message for the SP1 compressed verifier from
sp1-proofs/${circuit}.sp1-compressed-{proof.bytes,public.bin,vkey.bin}.

Default circuit: process-messages-native-2-1-5-full
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

circuit="${1:-process-messages-native-2-1-5-full}"
proof="sp1-proofs/${circuit}.sp1-compressed-proof.bytes"
public_values="sp1-proofs/${circuit}.sp1-compressed.public.bin"
vkey_hash="sp1-proofs/${circuit}.sp1-compressed.vkey.bin"

for path in "$proof" "$public_values" "$vkey_hash"; do
  if [[ ! -f "$path" ]]; then
    echo "missing artifact: $path" >&2
    exit 1
  fi
done

b64() {
  if base64 --help 2>&1 | grep -q -- '-w'; then
    base64 -w0 "$1"
  else
    base64 < "$1" | tr -d '\n'
  fi
}

printf '{"verify_compressed":{"proof":"%s","public_values":"%s","vkey_hash":"%s"}}\n' \
  "$(b64 "$proof")" \
  "$(b64 "$public_values")" \
  "$(b64 "$vkey_hash")"
