#!/usr/bin/env bash
set -euo pipefail

stages=(
  fifteen-signup-process-deactivate
  fifteen-signup-add-new-key
  fifteen-signup-process-messages-0
  fifteen-signup-process-messages-1
  fifteen-signup-process-messages-2
  fifteen-signup-tally-0
  fifteen-signup-tally-1
  fifteen-signup-tally-2
  fifteen-signup-tally-3
)

mkdir -p sp1-proofs logs metrics

for circuit in "${stages[@]}"; do
  echo "== proving ${circuit} =="
  scripts/run_bench.sh sp1-compressed "$circuit"
  scripts/make_cosmwasm_sp1_compressed_msg.sh "$circuit" \
    > "sp1-proofs/${circuit}.verify-compressed.msg.json"
done

process_messages=(
  sp1-proofs/fifteen-signup-process-messages-0.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-process-messages-1.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-process-messages-2.verify-compressed.msg.json
)
tallies=(
  sp1-proofs/fifteen-signup-tally-0.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-1.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-2.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-3.verify-compressed.msg.json
)

echo "== aggregating process messages =="
AGGREGATE_PREFIX=fifteen-signup-process-messages \
  scripts/run_sp1_aggregate_process_messages.sh "${process_messages[@]}"

echo "== aggregating tally =="
AGGREGATE_PREFIX=fifteen-signup-tally \
  scripts/run_sp1_aggregate_tally.sh "${tallies[@]}"

scripts/make_cosmwasm_sp1_aggregate_msg.sh process-messages \
  sp1-proofs/fifteen-signup-process-messages.aggregate \
  > sp1-proofs/fifteen-signup-process-messages.aggregate.verify-compressed-aggregate.msg.json
scripts/make_cosmwasm_sp1_aggregate_msg.sh tally \
  sp1-proofs/fifteen-signup-tally.aggregate \
  > sp1-proofs/fifteen-signup-tally.aggregate.verify-compressed-aggregate.msg.json

scripts/package_fifteen_signup_aggregate_artifacts.sh

echo "done"
