#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_crypto_profile.sh

Runs SP1 execute micro-profiles for PQC/crypto primitives used by AMACI.

Environment:
  OPS       Space-separated op list. Defaults to all hot primitives.
  ITERS     Override iteration count for every op.

Outputs:
  logs/sp1-crypto-profile-<stamp>.out
  metrics/sp1-crypto-profile-<stamp>.summary.tsv
  metrics/sp1-crypto-profile-<op>-<stamp>.metrics.txt
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

default_ops=(
  kem-decap
  kem-encap
  mldsa-verify
  kem-compact
  command-decrypt
)

if [[ -n "${OPS:-}" ]]; then
  # shellcheck disable=SC2206
  ops=(${OPS})
else
  ops=("${default_ops[@]}")
fi

stamp="$(date +%Y%m%d-%H%M%S)"
mkdir -p logs metrics

suite_log="logs/sp1-crypto-profile-${stamp}.out"
summary="metrics/sp1-crypto-profile-${stamp}.summary.tsv"
target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-target}"
host_binary="$target_dir/release/amaci-proof-sp1-crypto-profile-host"

metric_value() {
  local path="$1"
  local key="$2"
  if [[ ! -s "$path" ]]; then
    echo "missing"
    return
  fi
  awk -F= -v key="$key" '$1 == key { value = $2 } END { if (value != "") print value; else print "missing" }' "$path"
}

last_log_value() {
  local log="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value = $2 } END { if (value != "") print value; else print "missing" }' "$log"
}

max_rss_kbytes() {
  local time_out="$1"
  if [[ ! -s "$time_out" ]]; then
    echo "missing"
    return
  fi
  awk -F: '
    /Maximum resident set size/ {
      gsub(/^[ \t]+/, "", $2)
      if (($2 + 0) > max) max = $2 + 0
    }
    END { if (max > 0) print max; else print "missing" }
  ' "$time_out"
}

elapsed_wall_values() {
  local time_out="$1"
  if [[ ! -s "$time_out" ]]; then
    echo "missing"
    return
  fi
  awk -F: '
    /Elapsed \(wall clock\) time/ {
      value = $2
      for (i = 3; i <= NF; i++) value = value ":" $i
      gsub(/^[ \t]+/, "", value)
      values = values ? values "," value : value
    }
    END { if (values != "") print values; else print "missing" }
  ' "$time_out"
}

printf "op\tmetrics\titers\tinput_bytes\tpublic_bytes\tinstructions\tinstructions_per_iter\tsyscalls\ttouched_memory_addresses\tmax_rss_kbytes\telapsed_wall_values\n" > "$summary"

{
  echo "stamp=$stamp"
  echo "ops=${ops[*]}"
  echo "target_dir=$target_dir"
} > "$suite_log"

{
  echo "== sp1 crypto profile host build start $(date -Is) =="
  echo "+ env CARGO_TARGET_DIR=$target_dir cargo build --release -p amaci-proof-sp1-crypto-profile-host"
} >> "$suite_log"
env CARGO_TARGET_DIR="$target_dir" \
  cargo build --release -p amaci-proof-sp1-crypto-profile-host >> "$suite_log" 2>&1
[[ -x "$host_binary" ]] || {
  echo "missing SP1 crypto profile host binary: $host_binary" >&2
  exit 1
}
echo "== sp1 crypto profile host build end $(date -Is) ==" >> "$suite_log"

for op in "${ops[@]}"; do
  log="logs/sp1-crypto-profile-${op}-${stamp}.log"
  metrics="metrics/sp1-crypto-profile-${op}-${stamp}.metrics.txt"
  time_out="metrics/sp1-crypto-profile-${op}-${stamp}.time.txt"
  args=("$op")
  if [[ -n "${ITERS:-}" ]]; then
    args+=("--iters" "$ITERS")
  fi

  {
    echo "== sp1 crypto profile ${op} start $(date -Is) =="
    echo "+ $host_binary ${args[*]}"
  } >> "$suite_log"

  if /usr/bin/time -v true >/dev/null 2>&1; then
    /usr/bin/time -v -o "$time_out" \
      "$host_binary" "${args[@]}" \
        > "$log" 2>&1
  else
    "$host_binary" "${args[@]}" \
      > "$log" 2>&1
  fi

  {
    echo "backend=sp1-crypto-profile"
    echo "op=$op"
    echo "stamp=$stamp"
    echo "log=$log"
    echo "time_log=$time_out"
    echo "elapsed_wall_values=$(elapsed_wall_values "$time_out")"
    echo "max_rss_kbytes=$(max_rss_kbytes "$time_out")"
    echo "iters=$(last_log_value "$log" iters)"
    echo "input_bytes=$(last_log_value "$log" input_bytes)"
    echo "public_bytes=$(last_log_value "$log" public_bytes)"
    echo "instructions=$(last_log_value "$log" instructions)"
    echo "instructions_per_iter=$(last_log_value "$log" instructions_per_iter)"
    echo "syscalls=$(last_log_value "$log" syscalls)"
    echo "touched_memory_addresses=$(last_log_value "$log" touched_memory_addresses)"
    echo "gas=$(last_log_value "$log" gas)"
  } > "$metrics"

  {
    printf "%s\t%s\t" "$op" "$metrics"
    printf "%s\t" "$(metric_value "$metrics" iters)"
    printf "%s\t" "$(metric_value "$metrics" input_bytes)"
    printf "%s\t" "$(metric_value "$metrics" public_bytes)"
    printf "%s\t" "$(metric_value "$metrics" instructions)"
    printf "%s\t" "$(metric_value "$metrics" instructions_per_iter)"
    printf "%s\t" "$(metric_value "$metrics" syscalls)"
    printf "%s\t" "$(metric_value "$metrics" touched_memory_addresses)"
    printf "%s\t" "$(metric_value "$metrics" max_rss_kbytes)"
    printf "%s\n" "$(metric_value "$metrics" elapsed_wall_values)"
  } >> "$summary"

  {
    echo "log=$log"
    echo "metrics=$metrics"
    echo "== sp1 crypto profile ${op} end $(date -Is) =="
  } >> "$suite_log"
done

echo "done"
echo "suite_log=$suite_log"
echo "summary=$summary"
