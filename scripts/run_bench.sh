#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_bench.sh risc0 [circuit]
  scripts/run_bench.sh sp1 [circuit]
  scripts/run_bench.sh sp1-compressed [circuit]
  scripts/run_bench.sh sp1-groth16 [circuit]
  scripts/run_bench.sh sp1-execute [circuit]

The script writes backend logs to logs/ and timing/artifact metrics to metrics/.
USAGE
}

backend="${1:-}"
case "$backend" in
  risc0|sp1|sp1-compressed|sp1-groth16|sp1-execute) ;;
  -h|--help|"")
    usage
    exit 0
    ;;
  *)
    echo "unknown backend: $backend" >&2
    usage >&2
    exit 2
    ;;
esac

circuit="${2:-process-messages-native-2-1-5-full}"
stamp="$(date +%Y%m%d-%H%M%S)"
mkdir -p logs metrics proofs sp1-proofs

log="logs/${backend}-${circuit}-${stamp}.log"
metrics="metrics/${backend}-${circuit}-${stamp}.metrics.txt"
time_out="metrics/${backend}-${circuit}-${stamp}.time.txt"
: > "$time_out"

timed_labels=()
timed_time_logs=()

stat_size() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "missing"
  elif stat -c%s "$path" >/dev/null 2>&1; then
    stat -c%s "$path"
  else
    stat -f%z "$path"
  fi
}

last_log_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { value = $2 } END { if (value != "") print value; else print "missing" }' "$log"
}

max_rss_kbytes_from() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
    echo "missing"
    return
  fi
  awk -F: '
    /Maximum resident set size/ {
      gsub(/^[ \t]+/, "", $2)
      if (($2 + 0) > max) max = $2 + 0
    }
    END { if (max > 0) print max; else print "missing" }
  ' "$path"
}

elapsed_wall_values_from() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
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
  ' "$path"
}

max_rss_kbytes() {
  max_rss_kbytes_from "$time_out"
}

elapsed_wall_values() {
  elapsed_wall_values_from "$time_out"
}

run_timed() {
  local label="$1"
  shift
  local slug
  local command_time_out
  slug="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g')"
  command_time_out="${time_out%.time.txt}.${slug}.time.txt"
  : > "$command_time_out"
  {
    echo "== ${label} start $(date -Is) =="
    echo "+ $*"
  } >> "$log"
  if /usr/bin/time -v true >/dev/null 2>&1; then
    /usr/bin/time -v -o "$command_time_out" "$@" >> "$log" 2>&1
    cat "$command_time_out" >> "$time_out"
  else
    { time "$@"; } >> "$log" 2>&1
  fi
  echo "== ${label} end $(date -Is) ==" >> "$log"
  timed_labels+=("$label")
  timed_time_logs+=("$command_time_out")
}

build_sp1_host() {
  local target_dir="$1"
  SP1_HOST_BINARY="$target_dir/release/amaci-proof-sp1-host"
  {
    echo "== sp1 host build start $(date -Is) =="
    echo "+ env CARGO_TARGET_DIR=$target_dir cargo build --release -p amaci-proof-sp1-host"
  } >> "$log"
  env CARGO_TARGET_DIR="$target_dir" \
    cargo build --release -p amaci-proof-sp1-host >> "$log" 2>&1
  [[ -x "$SP1_HOST_BINARY" ]] || {
    echo "missing SP1 host binary: $SP1_HOST_BINARY" >&2
    exit 1
  }
  echo "== sp1 host build end $(date -Is) ==" >> "$log"
}

write_common_metrics() {
  {
    echo "backend=$backend"
    echo "circuit=$circuit"
    echo "stamp=$stamp"
    echo "log=$log"
    echo "time_log=$time_out"
    echo "elapsed_wall_values=$(elapsed_wall_values)"
    echo "max_rss_kbytes=$(max_rss_kbytes)"
    if [[ -n "${SP1_HOST_BINARY:-}" ]]; then
      echo "host_binary=$SP1_HOST_BINARY"
      local logged_shard_size
      logged_shard_size="$(last_log_value shard_size)"
      if [[ "$logged_shard_size" == "missing" ]]; then
        logged_shard_size="${SHARD_SIZE:-default}"
      fi
      echo "shard_size=$logged_shard_size"
      echo "global_dependencies_opt=$(last_log_value global_dependencies_opt)"
    fi
    local index label key phase_time_log
    for index in "${!timed_labels[@]}"; do
      label="${timed_labels[$index]}"
      phase_time_log="${timed_time_logs[$index]}"
      key="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g')"
      echo "${key}_time_log=$phase_time_log"
      echo "${key}_elapsed_wall=$(elapsed_wall_values_from "$phase_time_log")"
      echo "${key}_max_rss_kbytes=$(max_rss_kbytes_from "$phase_time_log")"
    done
    echo "input_bytes=$(last_log_value input_bytes)"
    echo "public_values_bytes=$(last_log_value public_bytes)"
    echo "instructions=$(last_log_value instructions)"
    echo "syscalls=$(last_log_value syscalls)"
    echo "touched_memory_addresses=$(last_log_value touched_memory_addresses)"
    echo "gas=$(last_log_value gas)"
  } >> "$metrics"
}

run_risc0() {
  local target_dir="${RISC0_TARGET_DIR:-/tmp/zkvm-amaci-risc0-target}"
  local receipt="proofs/${circuit}.risc0.receipt.bin"
  local public="proofs/${circuit}.risc0.public.json"
  local verified_public="proofs/${circuit}.risc0.verified-public.json"

  run_timed "risc0 prove" \
    env RISC0_DEV_MODE="${RISC0_DEV_MODE:-0}" CARGO_TARGET_DIR="$target_dir" \
      cargo --config configs/cargo-risc0-native-patches.toml run --release \
      -p amaci-proof-risc0-host -- \
      prove "$circuit" \
      --receipt "$receipt" \
      --public "$public"

  run_timed "risc0 verify" \
    env RISC0_DEV_MODE="${RISC0_DEV_MODE:-0}" CARGO_TARGET_DIR="$target_dir" \
      cargo --config configs/cargo-risc0-native-patches.toml run --release \
      -p amaci-proof-risc0-host -- \
      verify \
      --receipt "$receipt" \
      --public "$verified_public"

  cmp -s "$public" "$verified_public"
  echo "risc0 public output match" >> "$log"

  write_common_metrics
  {
    echo "target_dir=$target_dir"
    echo "receipt=$receipt"
    echo "receipt_bytes=$(stat_size "$receipt")"
    echo "public=$public"
    echo "public_bytes=$(stat_size "$public")"
    echo "verified_public=$verified_public"
    echo "verified_public_bytes=$(stat_size "$verified_public")"
    echo "verify_cmp=ok"
  } >> "$metrics"
}

run_sp1() {
  local target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-target}"
  local proof="sp1-proofs/${circuit}.sp1-proof.bin"
  local public="sp1-proofs/${circuit}.sp1.public.json"
  local verified_public="sp1-proofs/${circuit}.sp1.verified-public.json"

  build_sp1_host "$target_dir"

  run_timed "sp1 prove" \
    "$SP1_HOST_BINARY" \
      prove "$circuit" \
      --proof "$proof" \
      --public "$public"

  run_timed "sp1 verify" \
    "$SP1_HOST_BINARY" \
      verify \
      --proof "$proof" \
      --public "$verified_public"

  cmp -s "$public" "$verified_public"
  echo "sp1 public output match" >> "$log"

  write_common_metrics
  {
    echo "target_dir=$target_dir"
    echo "proof=$proof"
    echo "proof_bytes=$(stat_size "$proof")"
    echo "public=$public"
    echo "public_bytes=$(stat_size "$public")"
    echo "verified_public=$verified_public"
    echo "verified_public_bytes=$(stat_size "$verified_public")"
    echo "verify_cmp=ok"
  } >> "$metrics"
}

run_sp1_groth16() {
  local target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-target}"
  local proof="sp1-proofs/${circuit}.sp1-groth16-proof.bin"
  local proof_bytes="sp1-proofs/${circuit}.sp1-groth16-proof.bytes"
  local public="sp1-proofs/${circuit}.sp1-groth16.public.json"
  local public_bytes="sp1-proofs/${circuit}.sp1-groth16.public.bin"
  local verified_public="sp1-proofs/${circuit}.sp1-groth16.verified-public.json"
  local vkey="sp1-proofs/${circuit}.sp1-groth16.vkey.txt"

  build_sp1_host "$target_dir"

  run_timed "sp1 groth16 prove" \
    "$SP1_HOST_BINARY" \
      prove-groth16 "$circuit" \
      --proof "$proof" \
      --proof-bytes "$proof_bytes" \
      --public "$public" \
      --public-bytes "$public_bytes" \
      --vkey "$vkey"

  run_timed "sp1 groth16 verify" \
    "$SP1_HOST_BINARY" \
      verify-groth16 \
      --proof-bytes "$proof_bytes" \
      --public-bytes "$public_bytes" \
      --vkey "$(tr -d '\n' < "$vkey")" \
      --public "$verified_public"

  cmp -s "$public" "$verified_public"
  echo "sp1 groth16 public output match" >> "$log"

  write_common_metrics
  {
    echo "target_dir=$target_dir"
    echo "proof=$proof"
    echo "proof_bytes_bincode=$(stat_size "$proof")"
    echo "proof_bytes=$proof_bytes"
    echo "proof_bytes_raw=$(stat_size "$proof_bytes")"
    echo "public=$public"
    echo "public_json_bytes=$(stat_size "$public")"
    echo "public_bytes=$public_bytes"
    echo "public_bytes_raw=$(stat_size "$public_bytes")"
    echo "verified_public=$verified_public"
    echo "verified_public_bytes=$(stat_size "$verified_public")"
    echo "vkey=$vkey"
    echo "verify_cmp=ok"
  } >> "$metrics"
}

run_sp1_compressed() {
  local target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-target}"
  local proof="sp1-proofs/${circuit}.sp1-compressed-proof.bin"
  local proof_bytes="sp1-proofs/${circuit}.sp1-compressed-proof.bytes"
  local public="sp1-proofs/${circuit}.sp1-compressed.public.json"
  local public_bytes="sp1-proofs/${circuit}.sp1-compressed.public.bin"
  local verified_public="sp1-proofs/${circuit}.sp1-compressed.verified-public.json"
  local vkey="sp1-proofs/${circuit}.sp1-compressed.vkey.bin"

  build_sp1_host "$target_dir"

  run_timed "sp1 compressed prove" \
    "$SP1_HOST_BINARY" \
      prove-compressed "$circuit" \
      --proof "$proof" \
      --proof-bytes "$proof_bytes" \
      --public "$public" \
      --public-bytes "$public_bytes" \
      --vkey "$vkey"

  run_timed "sp1 compressed verify" \
    "$SP1_HOST_BINARY" \
      verify-compressed \
      --proof-bytes "$proof_bytes" \
      --public-bytes "$public_bytes" \
      --vkey "$vkey" \
      --public "$verified_public"

  cmp -s "$public" "$verified_public"
  echo "sp1 compressed public output match" >> "$log"

  write_common_metrics
  {
    echo "target_dir=$target_dir"
    echo "proof=$proof"
    echo "proof_bytes_bincode=$(stat_size "$proof")"
    echo "proof_bytes=$proof_bytes"
    echo "proof_bytes_raw=$(stat_size "$proof_bytes")"
    echo "public=$public"
    echo "public_json_bytes=$(stat_size "$public")"
    echo "public_bytes=$public_bytes"
    echo "public_bytes_raw=$(stat_size "$public_bytes")"
    echo "verified_public=$verified_public"
    echo "verified_public_bytes=$(stat_size "$verified_public")"
    echo "vkey=$vkey"
    echo "vkey_bytes=$(stat_size "$vkey")"
    echo "verify_cmp=ok"
  } >> "$metrics"
}

run_sp1_execute() {
  local target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-target}"
  local public="sp1-proofs/${circuit}.sp1.execute-public.json"

  build_sp1_host "$target_dir"

  run_timed "sp1 execute" \
    "$SP1_HOST_BINARY" \
      execute "$circuit" \
      --public "$public"

  write_common_metrics
  {
    echo "target_dir=$target_dir"
    echo "public=$public"
    echo "public_bytes=$(stat_size "$public")"
  } >> "$metrics"
}

echo "log=$log"
echo "metrics=$metrics"

case "$backend" in
  risc0) run_risc0 ;;
  sp1) run_sp1 ;;
  sp1-compressed) run_sp1_compressed ;;
  sp1-groth16) run_sp1_groth16 ;;
  sp1-execute) run_sp1_execute ;;
esac

echo "done"
echo "log=$log"
echo "metrics=$metrics"
