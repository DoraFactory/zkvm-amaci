#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_tree_shard_sweep.sh PREFIX [PROCESS_CHILD_COUNT] [TALLY_CHILD_COUNT]

Benchmarks recursive tree proving with existing compressed child proofs. Each
shard size uses a separate output directory, so cached nodes cannot hide prove
time. Child proofs are never regenerated.

Environment:
  SHARD_SIZES     Space-separated powers of two. Default: 16777216 8388608 4194304
  SP1_TARGET_DIR  Shared Cargo target directory.

Outputs:
  logs/sp1-tree-shard-sweep-<stamp>.out
  metrics/sp1-tree-shard-sweep-<prefix>-<stamp>.summary.tsv
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage
  exit 2
fi

prefix="$1"
process_count="${2:-5}"
tally_count="${3:-1}"
if ! [[ "$process_count" =~ ^[1-9][0-9]*$ && "$tally_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "child counts must be positive integers" >&2
  exit 2
fi

target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-tree-shard-sweep-target}"
stamp="$(date +%Y%m%d-%H%M%S)"
suite_log="logs/sp1-tree-shard-sweep-${stamp}.out"
summary="metrics/sp1-tree-shard-sweep-${prefix}-${stamp}.summary.tsv"
host_binary="$target_dir/release/amaci-proof-sp1-tree-host"

if [[ -n "${SHARD_SIZES:-}" ]]; then
  # shellcheck disable=SC2206
  shard_sizes=(${SHARD_SIZES})
else
  shard_sizes=(16777216 8388608 4194304)
fi

process_children=()
for ((i = 0; i < process_count; i++)); do
  process_children+=("sp1-proofs/${prefix}-process-messages-${i}.sp1-compressed-proof.bin")
done
tally_children=()
for ((i = 0; i < tally_count; i++)); do
  tally_children+=("sp1-proofs/${prefix}-tally-${i}.sp1-compressed-proof.bin")
done
for child in "${process_children[@]}" "${tally_children[@]}"; do
  if [[ ! -s "$child" ]]; then
    echo "missing child proof: $child" >&2
    exit 1
  fi
done

mkdir -p logs metrics sp1-proofs
printf "shard_size\telapsed_wall\tmax_rss_kbytes\tprocess_node_elapsed_ms\ttally_node_elapsed_ms\tfinalization_elapsed_ms\tproof_bytes\tverify\n" > "$summary"

{
  echo "== sp1 tree host build start $(date -Is) =="
  env CARGO_TARGET_DIR="$target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml build --release \
      -p amaci-proof-sp1-tree-host
  echo "== sp1 tree host build end $(date -Is) =="
} >> "$suite_log" 2>&1

for shard_size in "${shard_sizes[@]}"; do
  if ! [[ "$shard_size" =~ ^[0-9]+$ ]] \
    || (( shard_size <= 0 || shard_size > 16777216 || (shard_size & (shard_size - 1)) != 0 )); then
    echo "invalid SHARD_SIZE: $shard_size; expected a power of two up to 16777216" >&2
    exit 2
  fi

  output_dir="sp1-proofs/${prefix}-tree-shard-${shard_size}-${stamp}"
  run_log="logs/sp1-tree-shard-${prefix}-${shard_size}-${stamp}.log"
  time_log="metrics/sp1-tree-shard-${prefix}-${shard_size}-${stamp}.time.txt"
  args=(build-finalization)
  for child in "${process_children[@]}"; do
    args+=(--process-child "$child")
  done
  for child in "${tally_children[@]}"; do
    args+=(--tally-child "$child")
  done
  args+=(--output-dir "$output_dir")

  echo "== shard_size=$shard_size start $(date -Is) ==" | tee -a "$suite_log"
  /usr/bin/time -v -o "$time_log" \
    env SHARD_SIZE="$shard_size" "$host_binary" "${args[@]}" \
      > "$run_log" 2>&1

  "$host_binary" verify-finalization \
      --proof-bytes "$output_dir/finalization-root.proof.bytes" \
      --public-bytes "$output_dir/finalization-root.public.bin" \
      --vkey "$output_dir/finalization-root.vkey.bin" \
      >> "$run_log" 2>&1

  process_metrics="$output_dir/process-messages/level-001/node-00000.metrics.json"
  tally_metrics="$output_dir/tally/level-001/node-00000.metrics.json"
  finalization_metrics="$output_dir/finalization-root.metrics.json"
  json_value() {
    local file="$1"
    local key="$2"
    sed -n "s/.*\"${key}\": \([0-9][0-9]*\).*/\1/p" "$file"
  }
  elapsed_wall="$(awk -F': ' '/Elapsed \(wall clock\) time/ { print $2 }' "$time_log")"
  max_rss="$(awk -F': ' '/Maximum resident set size/ { print $2 }' "$time_log")"
  proof_bytes="$(wc -c < "$output_dir/finalization-root.proof.bytes" | tr -d ' ')"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\tok\n" \
    "$shard_size" "$elapsed_wall" "$max_rss" \
    "$(json_value "$process_metrics" elapsed_ms)" \
    "$(json_value "$tally_metrics" elapsed_ms)" \
    "$(json_value "$finalization_metrics" elapsed_ms)" \
    "$proof_bytes" >> "$summary"
  echo "== shard_size=$shard_size end $(date -Is) ==" | tee -a "$suite_log"
done

echo "done"
echo "suite_log=$suite_log"
echo "summary=$summary"
