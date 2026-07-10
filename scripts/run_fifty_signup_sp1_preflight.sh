#!/usr/bin/env bash
set -euo pipefail

target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-fifty-target}"
stamp="$(date +%Y%m%d-%H%M%S)"
summary="metrics/fifty-signup-preflight-${stamp}.summary.tsv"
circuits=(
  fifty-signup-process-deactivate
  fifty-signup-process-messages-0
  fifty-signup-tally-0
)

mkdir -p logs metrics sp1-proofs
printf 'circuit\tmetrics\tinput_bytes\tpublic_values_bytes\tinstructions\tgas\tmax_rss_kbytes\n' > "$summary"

metric_value() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { if (value != "") print value; else print "missing" }' "$path"
}

for circuit in "${circuits[@]}"; do
  SP1_TARGET_DIR="$target_dir" scripts/run_bench.sh sp1-execute "$circuit"
  metric="$(find metrics -maxdepth 1 -type f -name "sp1-execute-${circuit}-*.metrics.txt" -print0 | xargs -0 ls -t | head -1)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$circuit" \
    "$metric" \
    "$(metric_value "$metric" input_bytes)" \
    "$(metric_value "$metric" public_values_bytes)" \
    "$(metric_value "$metric" instructions)" \
    "$(metric_value "$metric" gas)" \
    "$(metric_value "$metric" max_rss_kbytes)" \
    >> "$summary"
done

echo "fifty signup SP1 preflight ok"
echo "summary=$summary"
