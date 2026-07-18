#!/usr/bin/env bash
set -euo pipefail

mode="${1:-execute}"
case "$mode" in
  execute)
    backend="sp1-execute"
    ;;
  compressed)
    backend="sp1-compressed"
    ;;
  *)
    echo "usage: $0 [execute|compressed]" >&2
    exit 2
    ;;
esac

target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-hundred-9315-target}"
stamp="$(date +%Y%m%d-%H%M%S)"
summary="metrics/hundred-signup-9-3-1-5-${mode}-${stamp}.summary.tsv"
circuits=(
  hundred-signup-process-deactivate
  hundred-signup-add-new-key
)
for batch_num in $(seq 0 19); do
  circuits+=("hundred-signup-process-messages-${batch_num}")
done
circuits+=(hundred-signup-tally-0)

mkdir -p logs metrics sp1-proofs
printf 'backend\tcircuit\tmetrics\tinput_bytes\tpublic_values_bytes\tinstructions\tsyscalls\tgas\tmax_rss_kbytes\tproof_bytes_raw\tverify_cmp\n' > "$summary"

metric_value() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { if (value != "") print value; else print "missing" }' "$path"
}

for circuit in "${circuits[@]}"; do
  SP1_TARGET_DIR="$target_dir" scripts/run_bench.sh "$backend" "$circuit"
  metric="$(find metrics -maxdepth 1 -type f -name "${backend}-${circuit}-*.metrics.txt" -print0 | xargs -0 ls -t | head -1)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$backend" \
    "$circuit" \
    "$metric" \
    "$(metric_value "$metric" input_bytes)" \
    "$(metric_value "$metric" public_values_bytes)" \
    "$(metric_value "$metric" instructions)" \
    "$(metric_value "$metric" syscalls)" \
    "$(metric_value "$metric" gas)" \
    "$(metric_value "$metric" max_rss_kbytes)" \
    "$(metric_value "$metric" proof_bytes_raw)" \
    "$(metric_value "$metric" verify_cmp)" \
    >> "$summary"
done

echo "hundred signup 9-3-1-5 SP1 ${mode} round ok"
echo "stage_count=${#circuits[@]}"
echo "summary=$summary"
