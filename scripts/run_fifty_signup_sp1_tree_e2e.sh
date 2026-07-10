#!/usr/bin/env bash
set -euo pipefail

prefix="fifty-signup"
stamp="$(date +%Y%m%d-%H%M%S)"
base_target_dir="${SP1_TARGET_DIR:-/tmp/zkvm-amaci-sp1-fifty-target}"
tree_target_dir="${TREE_TARGET_DIR:-/tmp/zkvm-amaci-sp1-tree-target}"
force_reprove="${FORCE_REPROVE:-0}"
base_archive="sp1-proofs/fifty-signup-base-messages.tar.gz"
suite_summary="metrics/fifty-signup-tree-suite-${stamp}.summary.tsv"

mkdir -p logs metrics sp1-proofs

stages=(
  fifty-signup-process-deactivate
  fifty-signup-add-new-key
)

printf 'kind\tcircuit\tmetrics\tinput_bytes\tmax_rss_kbytes\tproof_bytes\telapsed_wall\n' > "$suite_summary"

metric_value() {
  local path="$1"
  local key="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "missing"
    return
  fi
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { if (value != "") print value; else print "missing" }' "$path"
}

latest_metric() {
  local pattern="$1"
  local latest=""
  local path
  while IFS= read -r path; do
    if [[ -z "$latest" || "$path" -nt "$latest" ]]; then
      latest="$path"
    fi
  done < <(compgen -G "$pattern" || true)
  echo "$latest"
}
for ((i = 0; i < 10; i++)); do
  stages+=("fifty-signup-process-messages-${i}")
done
for ((i = 0; i < 11; i++)); do
  stages+=("fifty-signup-tally-${i}")
done

artifacts_complete() {
  local circuit="$1"
  local suffix
  for suffix in \
    sp1-compressed-proof.bin \
    sp1-compressed-proof.bytes \
    sp1-compressed.public.bin \
    sp1-compressed.public.json \
    sp1-compressed.vkey.bin; do
    [[ -s "sp1-proofs/${circuit}.${suffix}" ]] || return 1
  done
}

verify_existing() {
  local circuit="$1"
  local full_verified="sp1-proofs/${circuit}.sp1-compressed.resume-full-public.json"
  local raw_verified="sp1-proofs/${circuit}.sp1-compressed.resume-raw-public.json"
  env CARGO_TARGET_DIR="$base_target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml run --release \
      -p amaci-proof-sp1-host -- \
      verify-compressed \
      --proof "sp1-proofs/${circuit}.sp1-compressed-proof.bin" \
      --public "$full_verified"
  env CARGO_TARGET_DIR="$base_target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml run --release \
      -p amaci-proof-sp1-host -- \
      verify-compressed \
      --proof-bytes "sp1-proofs/${circuit}.sp1-compressed-proof.bytes" \
      --public-bytes "sp1-proofs/${circuit}.sp1-compressed.public.bin" \
      --vkey "sp1-proofs/${circuit}.sp1-compressed.vkey.bin" \
      --public "$raw_verified"
  cmp -s "sp1-proofs/${circuit}.sp1-compressed.public.json" "$full_verified"
  cmp -s "$full_verified" "$raw_verified"
}

message_paths=()
for circuit in "${stages[@]}"; do
  if [[ "$force_reprove" != "1" ]] && artifacts_complete "$circuit"; then
    echo "== resume and verify ${circuit} =="
    verify_existing "$circuit"
  else
    echo "== proving ${circuit} =="
    SP1_TARGET_DIR="$base_target_dir" scripts/run_bench.sh sp1-compressed "$circuit"
  fi
  local_msg="sp1-proofs/${circuit}.verify-compressed.msg.json"
  scripts/make_cosmwasm_sp1_compressed_msg.sh "$circuit" > "$local_msg"
  message_paths+=("${circuit}.verify-compressed.msg.json")
  circuit_metrics="$(latest_metric "metrics/sp1-compressed-${circuit}-*.metrics.txt")"
  printf 'base\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$circuit" \
    "${circuit_metrics:-missing}" \
    "$(metric_value "$circuit_metrics" input_bytes)" \
    "$(metric_value "$circuit_metrics" max_rss_kbytes)" \
    "$(metric_value "$circuit_metrics" proof_bytes_raw)" \
    "$(metric_value "$circuit_metrics" elapsed_wall_values)" \
    >> "$suite_summary"
done

tar -czf "$base_archive" -C sp1-proofs "${message_paths[@]}"

echo "== building fixed-fan-in tree round =="
CARGO_TARGET_DIR="$tree_target_dir" scripts/run_sp1_tree_round.sh "$prefix" 10 11
tree_metrics="$(latest_metric 'metrics/sp1-tree-fifty-signup-*.metrics.txt')"
printf 'tree\tround-root\t%s\tmissing\t%s\t%s\t%s\n' \
  "${tree_metrics:-missing}" \
  "$(metric_value "$tree_metrics" max_rss_kbytes)" \
  "$(metric_value "$tree_metrics" proof_bytes)" \
  "$(metric_value "$tree_metrics" elapsed_wall)" \
  >> "$suite_summary"

echo "fifty signup SP1 tree E2E artifacts ready"
echo "suite_summary=$suite_summary"
echo "base_archive=$base_archive"
echo "tree_archive=sp1-proofs/fifty-signup-tree-round-artifacts.tar.gz"
