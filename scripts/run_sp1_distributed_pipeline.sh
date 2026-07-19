#!/usr/bin/env bash
set -euo pipefail

DEFAULT_WORK_DIR="sp1-work/hundred-signup-9-3-1-5"
DEFAULT_SP1_TARGET_DIR="/tmp/zkvm-amaci-sp1-hundred-9315-target"
DEFAULT_TREE_TARGET_DIR="/tmp/zkvm-amaci-sp1-hundred-tree-target"

usage() {
  cat <<'USAGE'
usage:
  scripts/run_sp1_distributed_pipeline.sh prepare-witnesses [--work-dir PATH] [--force]
  scripts/run_sp1_distributed_pipeline.sh build-worker-bundle [--work-dir PATH] [--force]
  scripts/run_sp1_distributed_pipeline.sh prove-child --index N [--work-dir PATH] [--force]
  scripts/run_sp1_distributed_pipeline.sh status [--work-dir PATH]
  scripts/run_sp1_distributed_pipeline.sh aggregate-finalization [--work-dir PATH]

The default work directory is sp1-work/hundred-signup-9-3-1-5. Task indexes
are zero based. Frozen inputs and expected public values are covered by
checksums.sha256. Each successful worker emits a portable child package under
WORK_DIR/packages/.

Environment:
  SP1_TARGET_DIR   Base SP1 host target directory.
  TREE_TARGET_DIR  Recursive tree host target directory.
  SP1_HOST_BINARY  Prebuilt base host distributed by the coordinator.
  TREE_HOST_BINARY Prebuilt tree host retained by the coordinator.
  SHARD_SIZE       Optional SP1 compressed shard size.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

verify_checksum_file() {
  local root="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$root" && sha256sum -c checksums.sha256 >/dev/null)
  else
    (cd "$root" && shasum -a 256 -c checksums.sha256 >/dev/null)
  fi
}

verify_artifact_checksums() {
  local artifact_dir="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$artifact_dir" && sha256sum -c artifact-checksums.sha256 >/dev/null)
  else
    (cd "$artifact_dir" && shasum -a 256 -c artifact-checksums.sha256 >/dev/null)
  fi
}

write_artifact_checksums() {
  local artifact_dir="$1"
  shift
  : > "$artifact_dir/artifact-checksums.sha256"
  local name
  for name in "$@"; do
    printf '%s  %s\n' "$(sha256_file "$artifact_dir/$name")" "$name" \
      >> "$artifact_dir/artifact-checksums.sha256"
  done
}

result_value() {
  local artifact_dir="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { print value }' \
    "$artifact_dir/result.env"
}

stat_size() {
  local path="$1"
  if stat -c%s "$path" >/dev/null 2>&1; then
    stat -c%s "$path"
  else
    stat -f%z "$path"
  fi
}

task_line() {
  local work_dir="$1"
  local index="$2"
  awk -F $'\t' -v target="$index" '
    NR > 1 && $1 == target { print; found = 1 }
    END { if (!found) exit 1 }
  ' "$work_dir/tasks.tsv"
}

verify_pipeline() {
  local work_dir="$1"
  [[ -f "$work_dir/manifest.json" ]] || die "missing $work_dir/manifest.json"
  [[ -f "$work_dir/tasks.tsv" ]] || die "missing $work_dir/tasks.tsv"
  [[ -f "$work_dir/checksums.sha256" ]] || die "missing $work_dir/checksums.sha256"
  verify_checksum_file "$work_dir" || die "frozen pipeline checksum verification failed"
}

build_base_host() {
  local target_dir="$1"
  local log="$2"
  env CARGO_TARGET_DIR="$target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml build --release \
      -p amaci-proof-sp1-host >> "$log" 2>&1
}

build_tree_host() {
  local target_dir="$1"
  local log="$2"
  env CARGO_TARGET_DIR="$target_dir" \
    cargo --config configs/cargo-sp1-native-patches.toml build --release \
      -p amaci-proof-sp1-tree-host >> "$log" 2>&1
}

distributed_binary_is_valid() {
  local binary="$1"
  [[ -x "$binary" ]] || return 1
  local checksum_file="$(dirname "$binary")/$(basename "$binary").sha256"
  if [[ -f "$checksum_file" ]]; then
    if command -v sha256sum >/dev/null 2>&1; then
      (cd "$(dirname "$binary")" && sha256sum -c "$(basename "$checksum_file")" >/dev/null) \
        || return 1
    else
      (cd "$(dirname "$binary")" && shasum -a 256 -c "$(basename "$checksum_file")" >/dev/null) \
        || return 1
    fi
  fi
}

verify_distributed_binary() {
  distributed_binary_is_valid "$1" || die "host binary is missing or failed checksum: $1"
}

resolve_base_host() {
  local target_dir="$1"
  local log="$2"
  if [[ -n "${SP1_HOST_BINARY:-}" ]]; then
    verify_distributed_binary "$SP1_HOST_BINARY"
    printf '%s\n' "$SP1_HOST_BINARY"
  else
    build_base_host "$target_dir" "$log"
    printf '%s\n' "$target_dir/release/amaci-proof-sp1-host"
  fi
}

resolve_tree_host() {
  local target_dir="$1"
  local log="$2"
  if [[ -n "${TREE_HOST_BINARY:-}" ]]; then
    verify_distributed_binary "$TREE_HOST_BINARY"
    printf '%s\n' "$TREE_HOST_BINARY"
  else
    build_tree_host "$target_dir" "$log"
    printf '%s\n' "$target_dir/release/amaci-proof-sp1-tree-host"
  fi
}

info_value() {
  local output="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { print value }' \
    <<< "$output"
}

bundle_checksums_are_valid() {
  local bundle_dir="$1"
  [[ -f "$bundle_dir/bundle-checksums.sha256" ]] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$bundle_dir" && sha256sum -c bundle-checksums.sha256 >/dev/null)
  else
    (cd "$bundle_dir" && shasum -a 256 -c bundle-checksums.sha256 >/dev/null)
  fi
}

bundle_metadata_is_valid() {
  local bundle_dir="$1"
  [[ -f "$bundle_dir/bundle.env.sha256" ]] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$bundle_dir" && sha256sum -c bundle.env.sha256 >/dev/null)
  else
    (cd "$bundle_dir" && shasum -a 256 -c bundle.env.sha256 >/dev/null)
  fi
}

base_host_info() {
  local binary="$1"
  local bundle_dir
  bundle_dir="$(dirname "$binary")"
  if [[ "$(basename "$binary")" == "amaci-proof-sp1-host" ]] && \
    bundle_metadata_is_valid "$bundle_dir"; then
    local bundle_info
    bundle_info="$(cat "$bundle_dir/bundle.env")"
    echo "program_vkey_hash=$(info_value "$bundle_info" base_program_vkey_hash)"
    echo "compressed_vkey_hash=$(info_value "$bundle_info" base_compressed_vkey_hash)"
  else
    "$binary" program-info
  fi
}

tree_host_info() {
  local binary="$1"
  local bundle_dir
  bundle_dir="$(dirname "$binary")"
  if [[ "$(basename "$binary")" == "amaci-proof-sp1-tree-host" ]] && \
    bundle_metadata_is_valid "$bundle_dir"; then
    local bundle_info
    bundle_info="$(cat "$bundle_dir/bundle.env")"
    echo "base_program_vkey_hash=$(info_value "$bundle_info" base_program_vkey_hash)"
    echo "base_compressed_vkey_hash=$(info_value "$bundle_info" base_compressed_vkey_hash)"
    echo "tree_program_vkey_hash=$(info_value "$bundle_info" tree_program_vkey_hash)"
    echo "tree_compressed_vkey_hash=$(info_value "$bundle_info" tree_compressed_vkey_hash)"
  else
    "$binary" program-info
  fi
}

file_hex() {
  od -An -tx1 -v "$1" | tr -d ' \n'
}

host_info_pair_is_valid() {
  local base_info="$1"
  local tree_info="$2"
  local base_program tree_base_program base_compressed tree_base_compressed
  base_program="$(info_value "$base_info" program_vkey_hash)"
  tree_base_program="$(info_value "$tree_info" base_program_vkey_hash)"
  base_compressed="$(info_value "$base_info" compressed_vkey_hash)"
  tree_base_compressed="$(info_value "$tree_info" base_compressed_vkey_hash)"
  [[ -n "$base_program" && "$base_program" == "$tree_base_program" ]] || return 1
  [[ -n "$base_compressed" && "$base_compressed" == "$tree_base_compressed" ]]
}

host_pair_is_valid() {
  local base_info tree_info
  base_info="$(base_host_info "$1")" || return 1
  tree_info="$(tree_host_info "$2")" || return 1
  host_info_pair_is_valid "$base_info" "$tree_info"
}

verify_host_pair() {
  host_pair_is_valid "$1" "$2" \
    || die "base and tree hosts embed different base program vkeys"
}

worker_bundle_is_complete() {
  local bundle_dir="$1"
  local manifest_checksum="$2"
  [[ -f "$bundle_dir/bundle.env" ]] || return 1
  local bundle_info
  bundle_info="$(cat "$bundle_dir/bundle.env")"
  [[ "$(info_value "$bundle_info" manifest_checksum)" == "$manifest_checksum" ]] || return 1
  bundle_checksums_are_valid "$bundle_dir" || return 1
}

run_timed() {
  local time_log="$1"
  shift
  if /usr/bin/time -v true >/dev/null 2>&1; then
    /usr/bin/time -v -o "$time_log" "$@"
  else
    "$@"
  fi
}

artifact_is_complete() {
  local artifact_dir="$1"
  local expected_public="$2"
  local manifest_checksum="$3"
  local task_index="$4"
  local task_name="$5"
  [[ -f "$artifact_dir/result.env" ]] || return 1
  [[ -f "$artifact_dir/artifact-checksums.sha256" ]] || return 1
  [[ "$(result_value "$artifact_dir" manifest_checksum)" == "$manifest_checksum" ]] || return 1
  [[ "$(result_value "$artifact_dir" task_index)" == "$task_index" ]] || return 1
  [[ "$(result_value "$artifact_dir" task_name)" == "$task_name" ]] || return 1
  verify_artifact_checksums "$artifact_dir" || return 1
  cmp -s "$expected_public" "$artifact_dir/public.bin" || return 1
}

verify_compressed_artifact() {
  local binary="$1"
  local artifact_dir="$2"
  "$binary" verify-compressed \
    --proof-bytes "$artifact_dir/proof.bytes" \
    --public-bytes "$artifact_dir/public.bin" \
    --vkey "$artifact_dir/vkey.bin" >/dev/null
}

package_child() {
  local work_dir="$1"
  local artifact_relative="$2"
  local index="$3"
  local package_dir="$work_dir/packages"
  local padded
  padded="$(printf '%05d' "$index")"
  mkdir -p "$package_dir"
  local package="$package_dir/child-${padded}.tar.gz"
  local tmp="${package}.tmp.$$"
  tar -cf - -C "$work_dir" \
    "$artifact_relative/artifact-checksums.sha256" \
    "$artifact_relative/result.env" \
    "$artifact_relative/proof.bin" \
    "$artifact_relative/proof.bytes" \
    "$artifact_relative/public.json" \
    "$artifact_relative/public.bin" \
    "$artifact_relative/verified-public.json" \
    "$artifact_relative/vkey.bin" \
    "$artifact_relative/prove.log" \
    "$artifact_relative/prove.time.txt" \
    "$artifact_relative/verify.time.txt" \
    | gzip -n > "$tmp"
  mv "$tmp" "$package"
  echo "package=$package"
  echo "package_sha256=$(sha256_file "$package")"
}

prepare_witnesses() {
  local work_dir="$1"
  local force="$2"
  local witness_archive="${work_dir}-witnesses.tar.gz"
  if [[ "$force" == "0" ]] && [[ -f "$work_dir/checksums.sha256" ]] && \
    verify_checksum_file "$work_dir"; then
    local archive_tmp="${witness_archive}.tmp.$$"
    tar -czf "$archive_tmp" -C "$work_dir" \
      manifest.json tasks.tsv checksums.sha256 inputs expected-public
    mv "$archive_tmp" "$witness_archive"
    echo "prepare resume ok"
    echo "pipeline=$work_dir"
    echo "checksums_sha256=$(sha256_file "$work_dir/checksums.sha256")"
    echo "witness_archive=$witness_archive"
    echo "witness_archive_sha256=$(sha256_file "$witness_archive")"
    return
  fi
  if [[ -e "$work_dir" ]]; then
    [[ "$force" == "1" ]] || die "$work_dir exists but is incomplete; pass --force to replace it"
    mv "$work_dir" "${work_dir}.invalid-$(date +%Y%m%d-%H%M%S)"
  fi

  local tmp="${work_dir}.prepare.$$"
  rm -rf "$tmp"
  mkdir -p "$(dirname "$work_dir")"
  local revision
  revision="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  cargo run --release -p amaci-proof-core --bin export_hundred_signup_pipeline -- \
    "$tmp" "$revision"
  verify_checksum_file "$tmp" || die "exported pipeline checksum verification failed"
  mv "$tmp" "$work_dir"

  local archive_tmp="${witness_archive}.tmp.$$"
  tar -czf "$archive_tmp" -C "$work_dir" \
    manifest.json tasks.tsv checksums.sha256 inputs expected-public
  mv "$archive_tmp" "$witness_archive"
  echo "prepare witnesses ok"
  echo "pipeline=$work_dir"
  echo "task_count=$(($(wc -l < "$work_dir/tasks.tsv") - 1))"
  echo "checksums_sha256=$(sha256_file "$work_dir/checksums.sha256")"
  echo "witness_archive=$witness_archive"
  echo "witness_archive_sha256=$(sha256_file "$witness_archive")"
}

build_worker_bundle() {
  local work_dir="$1"
  local force="$2"
  verify_pipeline "$work_dir"
  local manifest_checksum
  manifest_checksum="$(sha256_file "$work_dir/checksums.sha256")"
  local base_target_dir="${SP1_TARGET_DIR:-$DEFAULT_SP1_TARGET_DIR}"
  local tree_target_dir="${TREE_TARGET_DIR:-$DEFAULT_TREE_TARGET_DIR}"
  local bundle_dir="$work_dir/worker-bundle"
  local archive="${work_dir}-worker-bundle.tar.gz"

  if [[ "$force" == "0" ]] && worker_bundle_is_complete "$bundle_dir" "$manifest_checksum"; then
    local archive_tmp="${archive}.tmp.$$"
    tar -cf - -C "$work_dir" worker-bundle | gzip -n > "$archive_tmp"
    mv "$archive_tmp" "$archive"
    echo "worker bundle resume ok"
    echo "bundle=$bundle_dir"
    echo "archive=$archive"
    echo "archive_sha256=$(sha256_file "$archive")"
    return
  fi
  if [[ -e "$bundle_dir" ]]; then
    [[ "$force" == "1" ]] \
      || die "$bundle_dir exists but is invalid; pass --force to replace it"
    mv "$bundle_dir" "${bundle_dir}.invalid-$(date +%Y%m%d-%H%M%S)"
  fi

  local log="$work_dir/worker-bundle-build.log"
  : > "$log"
  build_base_host "$base_target_dir" "$log"
  build_tree_host "$tree_target_dir" "$log"
  local base_binary="$base_target_dir/release/amaci-proof-sp1-host"
  local tree_binary="$tree_target_dir/release/amaci-proof-sp1-tree-host"
  local base_info tree_info
  base_info="$("$base_binary" program-info)"
  tree_info="$("$tree_binary" program-info)"
  host_info_pair_is_valid "$base_info" "$tree_info" \
    || die "base and tree hosts embed different base program vkeys"
  local tmp="${bundle_dir}.tmp.$$"
  mkdir -p "$tmp"
  cp "$base_binary" "$tmp/amaci-proof-sp1-host"
  cp "$tree_binary" "$tmp/amaci-proof-sp1-tree-host"
  chmod 0755 "$tmp/amaci-proof-sp1-host" "$tmp/amaci-proof-sp1-tree-host"
  printf '%s  %s\n' \
    "$(sha256_file "$tmp/amaci-proof-sp1-host")" amaci-proof-sp1-host \
    > "$tmp/amaci-proof-sp1-host.sha256"
  printf '%s  %s\n' \
    "$(sha256_file "$tmp/amaci-proof-sp1-tree-host")" amaci-proof-sp1-tree-host \
    > "$tmp/amaci-proof-sp1-tree-host.sha256"
  {
    echo "schema_version=1"
    echo "manifest_checksum=$manifest_checksum"
    echo "source_revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "base_program_vkey_hash=$(info_value "$base_info" program_vkey_hash)"
    echo "base_compressed_vkey_hash=$(info_value "$base_info" compressed_vkey_hash)"
    echo "tree_program_vkey_hash=$(info_value "$tree_info" tree_program_vkey_hash)"
    echo "tree_compressed_vkey_hash=$(info_value "$tree_info" tree_compressed_vkey_hash)"
    echo "base_host_sha256=$(sha256_file "$tmp/amaci-proof-sp1-host")"
    echo "tree_host_sha256=$(sha256_file "$tmp/amaci-proof-sp1-tree-host")"
  } > "$tmp/bundle.env"
  printf '%s  %s\n' "$(sha256_file "$tmp/bundle.env")" bundle.env \
    > "$tmp/bundle.env.sha256"
  : > "$tmp/bundle-checksums.sha256"
  local bundle_name
  for bundle_name in \
    amaci-proof-sp1-host amaci-proof-sp1-host.sha256 \
    amaci-proof-sp1-tree-host amaci-proof-sp1-tree-host.sha256 \
    bundle.env bundle.env.sha256; do
    printf '%s  %s\n' "$(sha256_file "$tmp/$bundle_name")" "$bundle_name" \
      >> "$tmp/bundle-checksums.sha256"
  done
  mv "$tmp" "$bundle_dir"
  worker_bundle_is_complete "$bundle_dir" "$manifest_checksum" \
    || die "built worker bundle failed self-verification"

  local archive_tmp="${archive}.tmp.$$"
  tar -cf - -C "$work_dir" worker-bundle | gzip -n > "$archive_tmp"
  mv "$archive_tmp" "$archive"
  echo "build worker bundle ok"
  echo "bundle=$bundle_dir"
  echo "base_program_vkey_hash=$(info_value "$base_info" program_vkey_hash)"
  echo "tree_program_vkey_hash=$(info_value "$tree_info" tree_program_vkey_hash)"
  echo "archive=$archive"
  echo "archive_sha256=$(sha256_file "$archive")"
}

prove_child() {
  local work_dir="$1"
  local index="$2"
  local force="$3"
  verify_pipeline "$work_dir"
  [[ "$index" =~ ^[0-9]+$ ]] || die "--index must be a non-negative integer"

  local line
  line="$(task_line "$work_dir" "$index")" || die "unknown task index $index"
  local task_index task_name task_stage input_relative expected_relative artifact_relative
  IFS=$'\t' read -r task_index task_name task_stage input_relative expected_relative artifact_relative \
    <<< "$line"
  local input_path="$work_dir/$input_relative"
  local expected_public="$work_dir/$expected_relative"
  local artifact_dir="$work_dir/$artifact_relative"
  local manifest_checksum
  manifest_checksum="$(sha256_file "$work_dir/checksums.sha256")"
  local target_dir="${SP1_TARGET_DIR:-$DEFAULT_SP1_TARGET_DIR}"
  local host_binary host_info expected_compressed_vkey

  if [[ "$force" == "0" ]] && artifact_is_complete \
    "$artifact_dir" "$expected_public" "$manifest_checksum" "$task_index" "$task_name"; then
    mkdir -p "$work_dir/resume-logs"
    local resume_log="$work_dir/resume-logs/${task_name}-$(date +%Y%m%d-%H%M%S).log"
    : > "$resume_log"
    host_binary="$(resolve_base_host "$target_dir" "$resume_log")"
    host_info="$(base_host_info "$host_binary")"
    expected_compressed_vkey="$(info_value "$host_info" compressed_vkey_hash)"
    [[ "$(file_hex "$artifact_dir/vkey.bin")" == "$expected_compressed_vkey" ]] \
      || die "cached task $task_index belongs to a different base program vkey"
    verify_compressed_artifact "$host_binary" "$artifact_dir"
    echo "prove child resume ok"
    echo "index=$task_index"
    echo "circuit=$task_name"
    package_child "$work_dir" "$artifact_relative" "$task_index"
    return
  fi
  if [[ -e "$artifact_dir" ]]; then
    [[ "$force" == "1" ]] || die "$artifact_dir exists but is invalid; pass --force to replace it"
    mv "$artifact_dir" "${artifact_dir}.invalid-$(date +%Y%m%d-%H%M%S)"
  fi

  local lock_dir="$work_dir/locks/${task_index}.lock"
  mkdir -p "$work_dir/locks"
  mkdir "$lock_dir" 2>/dev/null || die "task $task_index is already locked"
  trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT

  local tmp="${artifact_dir}.tmp.$$"
  mkdir -p "$tmp"
  local log="$tmp/prove.log"
  local prove_time="$tmp/prove.time.txt"
  local verify_time="$tmp/verify.time.txt"
  echo "index=$task_index" > "$log"
  echo "circuit=$task_name" >> "$log"
  echo "stage=$task_stage" >> "$log"
  echo "manifest_checksum=$manifest_checksum" >> "$log"
  echo "input_sha256=$(sha256_file "$input_path")" >> "$log"
  echo "== host build start $(date -Is) ==" >> "$log"
  host_binary="$(resolve_base_host "$target_dir" "$log")"
  echo "== host build end $(date -Is) ==" >> "$log"
  host_info="$(base_host_info "$host_binary")"
  expected_compressed_vkey="$(info_value "$host_info" compressed_vkey_hash)"

  run_timed "$prove_time" \
    "$host_binary" prove-compressed "$task_name" \
      --input "$input_path" \
      --proof "$tmp/proof.bin" \
      --proof-bytes "$tmp/proof.bytes" \
      --public "$tmp/public.json" \
      --public-bytes "$tmp/public.bin" \
      --vkey "$tmp/vkey.bin" >> "$log" 2>&1
  run_timed "$verify_time" \
    "$host_binary" verify-compressed \
      --proof-bytes "$tmp/proof.bytes" \
      --public-bytes "$tmp/public.bin" \
      --vkey "$tmp/vkey.bin" \
      --public "$tmp/verified-public.json" >> "$log" 2>&1
  cmp -s "$expected_public" "$tmp/public.bin" \
    || die "task $task_index public output does not match frozen expected output"
  [[ "$(file_hex "$tmp/vkey.bin")" == "$expected_compressed_vkey" ]] \
    || die "task $task_index prover emitted an unexpected base program vkey"

  {
    echo "schema_version=1"
    echo "manifest_checksum=$manifest_checksum"
    echo "task_index=$task_index"
    echo "task_name=$task_name"
    echo "task_stage=$task_stage"
    echo "input_sha256=$(sha256_file "$input_path")"
    echo "expected_public_sha256=$(sha256_file "$expected_public")"
    echo "proof_bytes=$(stat_size "$tmp/proof.bytes")"
    echo "public_bytes=$(stat_size "$tmp/public.bin")"
    echo "vkey_bytes=$(stat_size "$tmp/vkey.bin")"
    echo "program_vkey_hash=$(info_value "$host_info" program_vkey_hash)"
    echo "compressed_vkey_hash=$expected_compressed_vkey"
    echo "host_binary_sha256=$(sha256_file "$host_binary")"
    awk -F': ' '/Maximum resident set size/ { print "max_rss_kbytes=" $2 }' "$prove_time"
    awk -F': ' '/Elapsed \(wall clock\) time/ { print "elapsed_wall=" $2 }' "$prove_time"
    echo "verify=ok"
  } > "$tmp/result.env"
  write_artifact_checksums "$tmp" \
    proof.bin proof.bytes public.json public.bin verified-public.json vkey.bin result.env
  mv "$tmp" "$artifact_dir"
  trap - EXIT
  rmdir "$lock_dir"

  verify_compressed_artifact "$host_binary" "$artifact_dir"
  echo "prove child ok"
  echo "index=$task_index"
  echo "circuit=$task_name"
  echo "artifact=$artifact_dir"
  package_child "$work_dir" "$artifact_relative" "$task_index"
}

pipeline_status() {
  local work_dir="$1"
  verify_pipeline "$work_dir"
  local manifest_checksum
  manifest_checksum="$(sha256_file "$work_dir/checksums.sha256")"
  local expected_compressed_vkey=""
  local bundle_dir="$work_dir/worker-bundle"
  if worker_bundle_is_complete "$bundle_dir" "$manifest_checksum"; then
    expected_compressed_vkey="$(info_value \
      "$(cat "$bundle_dir/bundle.env")" base_compressed_vkey_hash)"
  fi
  printf 'index\tstage\tcircuit\tstatus\n'
  local ready=0
  local missing=0
  while IFS=$'\t' read -r index name stage input_relative expected_relative artifact_relative; do
    [[ "$index" == "index" ]] && continue
    local state="missing"
    if artifact_is_complete \
      "$work_dir/$artifact_relative" \
      "$work_dir/$expected_relative" \
      "$manifest_checksum" "$index" "$name"; then
      if [[ -n "$expected_compressed_vkey" ]] && \
        [[ "$(file_hex "$work_dir/$artifact_relative/vkey.bin")" != \
          "$expected_compressed_vkey" ]]; then
        state="incompatible-vkey"
        missing=$((missing + 1))
      else
        state="ready"
        ready=$((ready + 1))
      fi
    else
      missing=$((missing + 1))
    fi
    printf '%s\t%s\t%s\t%s\n' "$index" "$stage" "$name" "$state"
  done < "$work_dir/tasks.tsv"
  echo "ready=$ready"
  echo "missing_or_invalid=$missing"
  echo "manifest_checksum=$manifest_checksum"
}

aggregate_finalization() {
  local work_dir="$1"
  verify_pipeline "$work_dir"
  local manifest_checksum
  manifest_checksum="$(sha256_file "$work_dir/checksums.sha256")"
  local base_target_dir="${SP1_TARGET_DIR:-$DEFAULT_SP1_TARGET_DIR}"
  local tree_target_dir="${TREE_TARGET_DIR:-$DEFAULT_TREE_TARGET_DIR}"
  local base_binary tree_binary
  local aggregation_dir="$work_dir/aggregation"
  local output_dir="$work_dir/finalization-tree"
  mkdir -p "$aggregation_dir" "$output_dir"
  local log="$aggregation_dir/finalization.log"
  local time_log="$aggregation_dir/finalization.time.txt"
  : > "$log"

  local process_children=()
  local tally_children=()
  local child_artifacts=()
  local first_vkey=""
  while IFS=$'\t' read -r index name stage input_relative expected_relative artifact_relative; do
    [[ "$index" == "index" ]] && continue
    [[ "$stage" == "process_messages" || "$stage" == "tally" ]] || continue
    local artifact_dir="$work_dir/$artifact_relative"
    artifact_is_complete \
      "$artifact_dir" "$work_dir/$expected_relative" "$manifest_checksum" "$index" "$name" \
      || die "child task $index ($name) is missing or invalid"
    if [[ -z "$first_vkey" ]]; then
      first_vkey="$artifact_dir/vkey.bin"
    else
      cmp -s "$first_vkey" "$artifact_dir/vkey.bin" \
        || die "child task $index uses a different base program vkey"
    fi
    child_artifacts+=("$artifact_dir")
    case "$stage" in
      process_messages) process_children+=("$artifact_dir/proof.bin") ;;
      tally) tally_children+=("$artifact_dir/proof.bin") ;;
    esac
  done < "$work_dir/tasks.tsv"
  [[ "${#process_children[@]}" -gt 0 ]] || die "no process-message child proofs"
  [[ "${#tally_children[@]}" -gt 0 ]] || die "no tally child proofs"

  base_binary="$(resolve_base_host "$base_target_dir" "$log")"
  tree_binary="$(resolve_tree_host "$tree_target_dir" "$log")"
  verify_host_pair "$base_binary" "$tree_binary"
  local base_info expected_compressed_vkey
  base_info="$(base_host_info "$base_binary")"
  expected_compressed_vkey="$(info_value "$base_info" compressed_vkey_hash)"
  [[ "$(file_hex "$first_vkey")" == "$expected_compressed_vkey" ]] \
    || die "child proofs do not belong to the base program embedded by the tree host"
  local artifact_dir
  for artifact_dir in "${child_artifacts[@]}"; do
    verify_compressed_artifact "$base_binary" "$artifact_dir"
  done

  local tree_args=(build-finalization)
  local child
  for child in "${process_children[@]}"; do
    tree_args+=(--process-child "$child")
  done
  for child in "${tally_children[@]}"; do
    tree_args+=(--tally-child "$child")
  done
  tree_args+=(--output-dir "$output_dir")

  {
    echo "manifest_checksum=$manifest_checksum"
    echo "process_messages_leaf_count=${#process_children[@]}"
    echo "tally_leaf_count=${#tally_children[@]}"
    echo "== finalization build start $(date -Is) =="
  } >> "$log"
  run_timed "$time_log" "$tree_binary" "${tree_args[@]}" >> "$log" 2>&1
  "$tree_binary" verify-finalization \
    --proof-bytes "$output_dir/finalization-root.proof.bytes" \
    --public-bytes "$output_dir/finalization-root.public.bin" \
    --vkey "$output_dir/finalization-root.vkey.bin" >> "$log" 2>&1
  echo "== finalization verify end $(date -Is) ==" >> "$log"

  local archive="$work_dir/finalization-artifacts.tar.gz"
  local archive_tmp="${archive}.tmp.$$"
  tar -czf "$archive_tmp" -C "$work_dir" \
    manifest.json tasks.tsv checksums.sha256 \
    finalization-tree/contract-config.json \
    finalization-tree/close-checkpoint.json \
    finalization-tree/manifest.json \
    finalization-tree/finalization-root.proof.bytes \
    finalization-tree/finalization-root.public.bin \
    finalization-tree/finalization-root.public.json \
    finalization-tree/finalization-root.vkey.bin \
    finalization-tree/finalization-root.metrics.json \
    finalization-tree/finalization-root.verify-compressed.msg.json
  mv "$archive_tmp" "$archive"
  {
    echo "backend=sp1-distributed-tree-finalization"
    echo "manifest_checksum=$manifest_checksum"
    echo "process_messages_leaf_count=${#process_children[@]}"
    echo "tally_leaf_count=${#tally_children[@]}"
    echo "proof_bytes=$(stat_size "$output_dir/finalization-root.proof.bytes")"
    echo "public_bytes=$(stat_size "$output_dir/finalization-root.public.bin")"
    echo "vkey_bytes=$(stat_size "$output_dir/finalization-root.vkey.bin")"
    echo "archive=$archive"
    echo "archive_bytes=$(stat_size "$archive")"
    awk -F': ' '/Maximum resident set size/ { print "max_rss_kbytes=" $2 }' "$time_log"
    awk -F': ' '/Elapsed \(wall clock\) time/ { print "elapsed_wall=" $2 }' "$time_log"
    echo "verify=ok"
  } > "$aggregation_dir/finalization.metrics.txt"
  echo "aggregate finalization ok"
  echo "metrics=$aggregation_dir/finalization.metrics.txt"
  echo "archive=$archive"
  echo "archive_sha256=$(sha256_file "$archive")"
}

command_name="${1:-}"
case "$command_name" in
  -h|--help|"")
    usage
    exit 0
    ;;
esac
shift

work_dir="$DEFAULT_WORK_DIR"
index=""
force=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir)
      [[ $# -ge 2 ]] || die "missing path after --work-dir"
      work_dir="$2"
      shift 2
      ;;
    --index)
      [[ $# -ge 2 ]] || die "missing value after --index"
      index="$2"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$work_dir" && "$work_dir" != "/" ]] || die "unsafe work directory"
case "$command_name" in
  prepare-witnesses)
    [[ -z "$index" ]] || die "prepare-witnesses does not accept --index"
    prepare_witnesses "$work_dir" "$force"
    ;;
  build-worker-bundle)
    [[ -z "$index" ]] || die "build-worker-bundle does not accept --index"
    build_worker_bundle "$work_dir" "$force"
    ;;
  prove-child)
    [[ -n "$index" ]] || die "prove-child requires --index N"
    prove_child "$work_dir" "$index" "$force"
    ;;
  status)
    [[ -z "$index" ]] || die "status does not accept --index"
    pipeline_status "$work_dir"
    ;;
  aggregate-finalization)
    [[ -z "$index" ]] || die "aggregate-finalization does not accept --index"
    aggregate_finalization "$work_dir"
    ;;
  *)
    die "unknown command: $command_name"
    ;;
esac
