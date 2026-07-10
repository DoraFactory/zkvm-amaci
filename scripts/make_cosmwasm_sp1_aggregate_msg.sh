#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/make_cosmwasm_sp1_aggregate_msg.sh [process-messages|tally] [artifact-prefix]

Builds a CosmWasm execute message payload for the AMACI round aggregate verifier.

Defaults:
  process-messages

Artifact prefixes:
  process-messages -> sp1-proofs/five-signup-process-messages.aggregate
  tally            -> sp1-proofs/five-signup-tally.aggregate
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

kind="${1:-process-messages}"
case "$kind" in
  process-messages)
    default_prefix="sp1-proofs/five-signup-process-messages.aggregate"
    ;;
  tally)
    default_prefix="sp1-proofs/five-signup-tally.aggregate"
    ;;
  *)
    echo "unknown aggregate kind: $kind" >&2
    usage >&2
    exit 2
    ;;
esac
prefix="${2:-$default_prefix}"

proof="${prefix}.sp1-compressed-proof.bytes"
public_values="${prefix}.public.bin"
vkey_hash="${prefix}.vkey.bin"

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

printf '{"verify_compressed_aggregate":{"proof":"%s","public_values":"%s","vkey_hash":"%s"}}\n' \
  "$(b64 "$proof")" \
  "$(b64 "$public_values")" \
  "$(b64 "$vkey_hash")"
