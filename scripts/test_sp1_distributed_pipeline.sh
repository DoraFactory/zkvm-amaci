#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
runner="$repo_root/scripts/run_sp1_distributed_pipeline.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/amaci-sp1-pipeline-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

cd "$repo_root"
pipeline="$tmp/pipeline"
"$runner" prepare-witnesses --work-dir "$pipeline" > "$tmp/prepare.log"
grep -q '^prepare witnesses ok$' "$tmp/prepare.log"
grep -q '^task_count=23$' "$tmp/prepare.log"
first_witness_sha="$(hash_file "${pipeline}-witnesses.tar.gz")"

"$runner" prepare-witnesses --work-dir "$pipeline" > "$tmp/resume.log"
grep -q '^prepare resume ok$' "$tmp/resume.log"
grep -q '^witness_archive_sha256=' "$tmp/resume.log"
second_witness_sha="$(hash_file "${pipeline}-witnesses.tar.gz")"
[[ "$first_witness_sha" == "$second_witness_sha" ]]

"$runner" status --work-dir "$pipeline" > "$tmp/status.log"
grep -q '^ready=0$' "$tmp/status.log"
grep -q '^missing_or_invalid=23$' "$tmp/status.log"

tampered="$tmp/tampered"
cp -R "$pipeline" "$tampered"
printf 'tampered' >> "$tampered/inputs/hundred-signup-process-messages-0.input.bin"
if "$runner" status --work-dir "$tampered" > "$tmp/tampered.log" 2>&1; then
  echo "tampered frozen input unexpectedly passed" >&2
  exit 1
fi
grep -q 'frozen pipeline checksum verification failed' "$tmp/tampered.log"

if "$runner" prove-child --work-dir "$pipeline" --index 99 > "$tmp/index.log" 2>&1; then
  echo "unknown child index unexpectedly passed" >&2
  exit 1
fi
grep -q 'unknown task index 99' "$tmp/index.log"

mkdir -p "$pipeline/locks/0.lock"
if "$runner" prove-child --work-dir "$pipeline" --index 0 > "$tmp/lock.log" 2>&1; then
  echo "duplicate child worker unexpectedly acquired the lock" >&2
  exit 1
fi
grep -q 'task 0 is already locked' "$tmp/lock.log"

if "$runner" aggregate-finalization --work-dir "$pipeline" > "$tmp/aggregate.log" 2>&1; then
  echo "aggregation unexpectedly accepted missing children" >&2
  exit 1
fi
grep -q 'child task 2 .* is missing or invalid' "$tmp/aggregate.log"

echo "sp1 distributed pipeline tests ok"
