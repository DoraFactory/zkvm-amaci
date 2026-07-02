#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_profile_suite.sh [execute|compressed|both|native]

Runs a reproducible profiling suite for the AMACI zkVM circuits.

Environment:
  CIRCUITS       Space-separated circuit list. Defaults to the current AMACI hot paths.
  NATIVE_ITERS   Iterations for native proof-core profiling. Default: 200.

Outputs:
  logs/sp1-profile-suite-<stamp>.out
  metrics/sp1-profile-suite-<stamp>.summary.tsv
  metrics/native-profile-<circuit>-<stamp>.txt
USAGE
}

mode="${1:-execute}"
case "$mode" in
  execute|compressed|both|native) ;;
  -h|--help|"")
    usage
    exit 0
    ;;
  *)
    echo "unknown mode: $mode" >&2
    usage >&2
    exit 2
    ;;
esac

default_circuits=(
  five-signup-process-deactivate
  five-signup-add-new-key
  five-signup-process-messages-full
  five-signup-tally-0
  five-signup-tally-1
)

if [[ -n "${CIRCUITS:-}" ]]; then
  # shellcheck disable=SC2206
  circuits=(${CIRCUITS})
else
  circuits=("${default_circuits[@]}")
fi

native_iters="${NATIVE_ITERS:-200}"
stamp="$(date +%Y%m%d-%H%M%S)"
mkdir -p logs metrics proofs sp1-proofs

suite_log="logs/sp1-profile-suite-${stamp}.out"
summary="metrics/sp1-profile-suite-${stamp}.summary.tsv"

metric_value() {
  local path="$1"
  local key="$2"
  if [[ ! -s "$path" ]]; then
    echo "missing"
    return
  fi
  awk -F= -v key="$key" '$1 == key { value = $2 } END { if (value != "") print value; else print "missing" }' "$path"
}

latest_metric() {
  local backend="$1"
  local circuit="$2"
  ls -t "metrics/${backend}-${circuit}-"*.metrics.txt 2>/dev/null | head -1
}

append_summary() {
  local backend="$1"
  local circuit="$2"
  local metric_file="$3"
  {
    printf "%s\t%s\t%s\t" "$backend" "$circuit" "$metric_file"
    printf "%s\t" "$(metric_value "$metric_file" avg_execute_ms)"
    printf "%s\t" "$(metric_value "$metric_file" input_bytes)"
    printf "%s\t" "$(metric_value "$metric_file" public_values_bytes)"
    printf "%s\t" "$(metric_value "$metric_file" instructions)"
    printf "%s\t" "$(metric_value "$metric_file" syscalls)"
    printf "%s\t" "$(metric_value "$metric_file" touched_memory_addresses)"
    printf "%s\t" "$(metric_value "$metric_file" max_rss_kbytes)"
    printf "%s\t" "$(metric_value "$metric_file" proof_bytes_raw)"
    printf "%s\t" "$(metric_value "$metric_file" proof_bytes_bincode)"
    printf "%s\n" "$(metric_value "$metric_file" receipt_bytes)"
  } >> "$summary"
}

append_native_summary() {
  local circuit="$1"
  local metric_file="$2"
  {
    printf "native\t%s\t%s\t" "$circuit" "$metric_file"
    printf "%s\t" "$(metric_value "$metric_file" avg_execute_ms)"
    printf "%s\t" "$(metric_value "$metric_file" input_bytes)"
    printf "%s\t" "$(metric_value "$metric_file" public_bytes)"
    printf "missing\tmissing\tmissing\tmissing\tmissing\tmissing\tmissing\n"
  } >> "$summary"
}

{
  echo "stamp=$stamp"
  echo "mode=$mode"
  echo "native_iters=$native_iters"
  echo "circuits=${circuits[*]}"
} > "$suite_log"

printf "backend\tcircuit\tmetrics\tavg_execute_ms\tinput_bytes\tpublic_values_bytes\tinstructions\tsyscalls\ttouched_memory_addresses\tmax_rss_kbytes\tproof_bytes_raw\tproof_bytes_bincode\treceipt_bytes\n" > "$summary"

for circuit in "${circuits[@]}"; do
  native_out="metrics/native-profile-${circuit}-${stamp}.txt"
  {
    echo "== native profile ${circuit} start $(date -Is) =="
    cargo run --release -p amaci-proof-core --bin native_profile -- "$circuit" --iters "$native_iters"
    echo "== native profile ${circuit} end $(date -Is) =="
  } > "$native_out" 2>&1
  echo "native_profile=${native_out}" >> "$suite_log"
  append_native_summary "$circuit" "$native_out"

  if [[ "$mode" == "execute" || "$mode" == "both" ]]; then
    echo "== sp1 execute ${circuit} start $(date -Is) ==" >> "$suite_log"
    bash scripts/run_bench.sh sp1-execute "$circuit" >> "$suite_log" 2>&1
    metric_file="$(latest_metric sp1-execute "$circuit")"
    append_summary sp1-execute "$circuit" "$metric_file"
    echo "== sp1 execute ${circuit} end $(date -Is) ==" >> "$suite_log"
  fi

  if [[ "$mode" == "compressed" || "$mode" == "both" ]]; then
    echo "== sp1 compressed ${circuit} start $(date -Is) ==" >> "$suite_log"
    bash scripts/run_bench.sh sp1-compressed "$circuit" >> "$suite_log" 2>&1
    metric_file="$(latest_metric sp1-compressed "$circuit")"
    append_summary sp1-compressed "$circuit" "$metric_file"
    echo "== sp1 compressed ${circuit} end $(date -Is) ==" >> "$suite_log"
  fi
done

echo "done"
echo "suite_log=$suite_log"
echo "summary=$summary"
