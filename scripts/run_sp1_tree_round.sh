#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_tree_round.sh PREFIX PROCESS_CHILD_COUNT TALLY_CHILD_COUNT

Consumes full SP1 compressed SDK proofs named under sp1-proofs/, builds fixed
fan-in-5 process-message and tally trees, and exports one final round-root proof.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

prefix="$1"
process_count="$2"
tally_count="$3"
if ! [[ "$process_count" =~ ^[1-9][0-9]*$ && "$tally_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "child counts must be positive integers" >&2
  exit 2
fi

target_dir="${CARGO_TARGET_DIR:-/tmp/zkvm-amaci-sp1-tree-target}"
output_dir="sp1-proofs/${prefix}-tree"
stamp="$(date +%Y%m%d-%H%M%S)"
log="logs/sp1-tree-${prefix}-${stamp}.log"
time_log="metrics/sp1-tree-${prefix}-${stamp}.time.txt"
metrics="metrics/sp1-tree-${prefix}-${stamp}.metrics.txt"
archive="sp1-proofs/${prefix}-tree-round-artifacts.tar.gz"
deactivate="sp1-proofs/${prefix}-process-deactivate.sp1-compressed-proof.bin"
add_key="sp1-proofs/${prefix}-add-new-key.sp1-compressed-proof.bin"

mkdir -p logs metrics sp1-proofs "$output_dir"

process_children=()
for ((i = 0; i < process_count; i++)); do
  process_children+=("sp1-proofs/${prefix}-process-messages-${i}.sp1-compressed-proof.bin")
done
tally_children=()
for ((i = 0; i < tally_count; i++)); do
  tally_children+=("sp1-proofs/${prefix}-tally-${i}.sp1-compressed-proof.bin")
done

for child in "$deactivate" "$add_key" "${process_children[@]}" "${tally_children[@]}"; do
  if [[ ! -f "$child" ]]; then
    echo "missing child proof: $child" >&2
    exit 1
  fi
done

stat_size() {
  if stat -c %s "$1" >/dev/null 2>&1; then
    stat -c %s "$1"
  else
    stat -f %z "$1"
  fi
}

tree_args=(
  build-round
  --deactivate-proof "$deactivate"
  --add-key-proof "$add_key"
)
for child in "${process_children[@]}"; do
  tree_args+=(--process-child "$child")
done
for child in "${tally_children[@]}"; do
  tree_args+=(--tally-child "$child")
done
tree_args+=(--output-dir "$output_dir")

{
  echo "prefix=$prefix"
  echo "tree_fanout=5"
  echo "process_messages_leaf_count=$process_count"
  echo "tally_leaf_count=$tally_count"
  echo "output_dir=$output_dir"
  /usr/bin/time -v -o "$time_log" \
    env CARGO_TARGET_DIR="$target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml run --release \
      -p amaci-proof-sp1-tree-host -- "${tree_args[@]}"

  env CARGO_TARGET_DIR="$target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml run --release \
      -p amaci-proof-sp1-tree-host -- \
      verify-round \
      --proof-bytes "$output_dir/round-root.proof.bytes" \
      --public-bytes "$output_dir/round-root.public.bin" \
      --vkey "$output_dir/round-root.vkey.bin"

  archive_paths=(
    "${prefix}-tree/contract-config.json"
    "${prefix}-tree/manifest.json"
    "${prefix}-tree/round-root.proof.bytes"
    "${prefix}-tree/round-root.public.bin"
    "${prefix}-tree/round-root.public.json"
    "${prefix}-tree/round-root.vkey.bin"
    "${prefix}-tree/round-root.metrics.json"
    "${prefix}-tree/round-root.verify-compressed.msg.json"
  )
  tar -czf "$archive" -C sp1-proofs "${archive_paths[@]}"

  {
    echo "backend=sp1-tree-round"
    echo "prefix=$prefix"
    echo "stamp=$stamp"
    echo "fanout=5"
    echo "process_messages_leaf_count=$process_count"
    echo "tally_leaf_count=$tally_count"
    echo "target_dir=$target_dir"
    echo "output_dir=$output_dir"
    echo "log=$log"
    echo "time_log=$time_log"
    echo "proof_bytes=$(stat_size "$output_dir/round-root.proof.bytes")"
    echo "public_bytes=$(stat_size "$output_dir/round-root.public.bin")"
    echo "vkey_bytes=$(stat_size "$output_dir/round-root.vkey.bin")"
    echo "archive=$archive"
    echo "archive_bytes=$(stat_size "$archive")"
    awk -F': ' '/Maximum resident set size/ { print "max_rss_kbytes=" $2 }' "$time_log"
    awk -F': ' '/Elapsed \(wall clock\) time/ { print "elapsed_wall=" $2 }' "$time_log"
    echo "verify=ok"
  } > "$metrics"

  echo "tree round suite ok"
  echo "metrics=$metrics"
  echo "archive=$archive"
} 2>&1 | tee "$log"
