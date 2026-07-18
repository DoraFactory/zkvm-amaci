#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_aggregate_tally.sh [child-msg ...]

Aggregates SP1 compressed tally child proofs into one SP1 compressed aggregate proof.

Defaults:
  sp1-proofs/five-signup-tally-0.verify-compressed.msg.json
  sp1-proofs/five-signup-tally-1.verify-compressed.msg.json

Environment:
  CARGO_TARGET_DIR  Cargo target directory. Default: /tmp/zkvm-amaci-sp1-agg-target
  AGGREGATE_PREFIX  Artifact prefix. Default: five-signup-tally
  SHARD_SIZE        SP1 core shard size. Default: 8388608

Outputs:
  logs/sp1-aggregate-tally-<stamp>.log
  metrics/sp1-aggregate-tally-<stamp>.time.txt
  metrics/sp1-aggregate-tally-<stamp>.metrics.txt
  sp1-proofs/<AGGREGATE_PREFIX>.aggregate.*
USAGE
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

if [[ "$#" -gt 0 ]]; then
  child_msgs=("$@")
else
  child_msgs=(
    "sp1-proofs/five-signup-tally-0.verify-compressed.msg.json"
    "sp1-proofs/five-signup-tally-1.verify-compressed.msg.json"
  )
fi

for child_msg in "${child_msgs[@]}"; do
  if [[ ! -s "$child_msg" ]]; then
    echo "missing child msg: $child_msg" >&2
    exit 1
  fi
done

stamp="$(date +%Y%m%d-%H%M%S)"
target_dir="${CARGO_TARGET_DIR:-/tmp/zkvm-amaci-sp1-agg-target}"
aggregate_prefix="${AGGREGATE_PREFIX:-five-signup-tally}"
mkdir -p logs metrics sp1-proofs

log="logs/sp1-aggregate-tally-${stamp}.log"
time_log="metrics/sp1-aggregate-tally-${stamp}.time.txt"
metrics="metrics/sp1-aggregate-tally-${stamp}.metrics.txt"

proof="sp1-proofs/${aggregate_prefix}.aggregate.sp1-compressed-proof.bin"
proof_bytes="sp1-proofs/${aggregate_prefix}.aggregate.sp1-compressed-proof.bytes"
public="sp1-proofs/${aggregate_prefix}.aggregate.public.json"
public_bytes="sp1-proofs/${aggregate_prefix}.aggregate.public.bin"
vkey="sp1-proofs/${aggregate_prefix}.aggregate.vkey.bin"

child_args=()
for child_msg in "${child_msgs[@]}"; do
  child_args+=(--child-msg "$child_msg")
done

{
  echo "stamp=$stamp"
  echo "target_dir=$target_dir"
  echo "aggregate_prefix=$aggregate_prefix"
  printf "child_msgs=%s\n" "${child_msgs[*]}"
  echo "proof=$proof"
  echo "proof_bytes=$proof_bytes"
  echo "public=$public"
  echo "public_bytes=$public_bytes"
  echo "vkey=$vkey"
} > "$log"

/usr/bin/time -v -o "$time_log" \
  env CARGO_TARGET_DIR="$target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml run --release \
      -p amaci-proof-sp1-aggregate-host -- \
      aggregate-tally \
      "${child_args[@]}" \
      --proof "$proof" \
      --proof-bytes "$proof_bytes" \
      --public "$public" \
      --public-bytes "$public_bytes" \
      --vkey "$vkey" \
  >> "$log" 2>&1

{
  echo "backend=sp1-aggregate-tally"
  echo "stamp=$stamp"
  echo "log=$log"
  echo "time_log=$time_log"
  echo "target_dir=$target_dir"
  echo "aggregate_prefix=$aggregate_prefix"
  printf "child_msgs=%s\n" "${child_msgs[*]}"
  echo "child_count=${#child_msgs[@]}"
  echo "proof=$proof"
  echo "proof_bytes=$proof_bytes"
  echo "proof_bytes_raw=$(wc -c < "$proof_bytes" | tr -d ' ')"
  echo "proof_bincode_bytes=$(wc -c < "$proof" | tr -d ' ')"
  echo "public=$public"
  echo "public_json_bytes=$(wc -c < "$public" | tr -d ' ')"
  echo "public_bytes=$public_bytes"
  echo "public_bytes_raw=$(wc -c < "$public_bytes" | tr -d ' ')"
  echo "vkey=$vkey"
  echo "vkey_bytes=$(wc -c < "$vkey" | tr -d ' ')"
  awk -F= '$1 == "shard_size" { value = $2 } END { print "shard_size=" value }' "$log"
  awk '/Elapsed \\(wall clock\\) time/ { print "elapsed_wall_values="$0 }' "$time_log"
  awk '/Maximum resident set size/ { print "max_rss_kbytes="$6 }' "$time_log"
} > "$metrics"

echo "done"
echo "log=$log"
echo "time_log=$time_log"
echo "metrics=$metrics"
