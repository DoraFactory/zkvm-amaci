#!/usr/bin/env bash
set -euo pipefail

stages=(
  five-signup-process-deactivate
  five-signup-add-new-key
  five-signup-process-messages-full
  five-signup-tally-0
  five-signup-tally-1
)

mkdir -p sp1-proofs logs metrics

for circuit in "${stages[@]}"; do
  echo "== proving ${circuit} =="
  scripts/run_bench.sh sp1-compressed "${circuit}"
  scripts/make_cosmwasm_sp1_compressed_msg.sh "${circuit}" \
    > "sp1-proofs/${circuit}.verify-compressed.msg.json"
  echo "msg=sp1-proofs/${circuit}.verify-compressed.msg.json"
done

echo "done"
