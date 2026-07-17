#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_shard_sweep.sh [circuit]

Runs sequential SP1 compressed-proof benchmarks with several core shard sizes.
The proof artifacts are overwritten on each run; timing metrics are retained.

Environment:
  SHARD_SIZES     Space-separated powers of two. Default: 16777216 8388608 4194304
  SP1_TARGET_DIR  Shared Cargo target directory.

Outputs:
  logs/sp1-shard-sweep-<stamp>.out
  metrics/sp1-shard-sweep-<circuit>-<stamp>.summary.tsv
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

circuit="${1:-five-signup-process-messages-full}"
target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-shard-sweep-target}"
stamp="$(date +%Y%m%d-%H%M%S)"
suite_log="logs/sp1-shard-sweep-${stamp}.out"
summary="metrics/sp1-shard-sweep-${circuit}-${stamp}.summary.tsv"

if [[ -n "${SHARD_SIZES:-}" ]]; then
  # shellcheck disable=SC2206
  shard_sizes=(${SHARD_SIZES})
else
  shard_sizes=(16777216 8388608 4194304)
fi

mkdir -p logs metrics sp1-proofs
printf "shard_size\tmetrics\tprove_elapsed_wall\tprove_max_rss_kbytes\tverify_elapsed_wall\tverify_max_rss_kbytes\tproof_bytes_raw\tverify_cmp\n" > "$summary"

metric_value() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value = $2 } END { if (value != "") print value; else print "missing" }' "$path"
}

for shard_size in "${shard_sizes[@]}"; do
  if ! [[ "$shard_size" =~ ^[0-9]+$ ]] \
    || (( shard_size <= 0 || shard_size > 16777216 || (shard_size & (shard_size - 1)) != 0 )); then
    echo "invalid SHARD_SIZE: $shard_size; expected a power of two up to 16777216" >&2
    exit 2
  fi

  {
    echo "== shard_size=$shard_size start $(date -Is) =="
    echo "+ env SHARD_SIZE=$shard_size SP1_TARGET_DIR=$target_dir scripts/run_bench.sh sp1-compressed $circuit"
  } >> "$suite_log"

  env SHARD_SIZE="$shard_size" SP1_TARGET_DIR="$target_dir" \
    bash scripts/run_bench.sh sp1-compressed "$circuit" >> "$suite_log" 2>&1

  metric_file="$(ls -t "metrics/sp1-compressed-${circuit}-"*.metrics.txt | head -1)"
  {
    printf "%s\t%s\t" "$shard_size" "$metric_file"
    printf "%s\t" "$(metric_value "$metric_file" sp1_compressed_prove_elapsed_wall)"
    printf "%s\t" "$(metric_value "$metric_file" sp1_compressed_prove_max_rss_kbytes)"
    printf "%s\t" "$(metric_value "$metric_file" sp1_compressed_verify_elapsed_wall)"
    printf "%s\t" "$(metric_value "$metric_file" sp1_compressed_verify_max_rss_kbytes)"
    printf "%s\t" "$(metric_value "$metric_file" proof_bytes_raw)"
    printf "%s\n" "$(metric_value "$metric_file" verify_cmp)"
  } >> "$summary"

  echo "== shard_size=$shard_size end $(date -Is) ==" >> "$suite_log"
done

echo "done"
echo "suite_log=$suite_log"
echo "summary=$summary"
