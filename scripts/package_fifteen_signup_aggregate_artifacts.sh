#!/usr/bin/env bash
set -euo pipefail

archive="${1:-sp1-proofs/fifteen-signup-aggregate-artifacts.tar.gz}"
files=(
  sp1-proofs/fifteen-signup-process-deactivate.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-add-new-key.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-process-messages-0.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-process-messages-1.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-process-messages-2.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-0.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-1.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-2.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-tally-3.verify-compressed.msg.json
  sp1-proofs/fifteen-signup-process-messages.aggregate.sp1-compressed-proof.bytes
  sp1-proofs/fifteen-signup-process-messages.aggregate.public.bin
  sp1-proofs/fifteen-signup-process-messages.aggregate.vkey.bin
  sp1-proofs/fifteen-signup-tally.aggregate.sp1-compressed-proof.bytes
  sp1-proofs/fifteen-signup-tally.aggregate.public.bin
  sp1-proofs/fifteen-signup-tally.aggregate.vkey.bin
  sp1-proofs/fifteen-signup-process-messages.aggregate.verify-compressed-aggregate.msg.json
  sp1-proofs/fifteen-signup-tally.aggregate.verify-compressed-aggregate.msg.json
)

for path in "${files[@]}"; do
  if [[ ! -s "$path" ]]; then
    echo "missing artifact: $path" >&2
    exit 1
  fi
done

tar -czf "$archive" "${files[@]}"
echo "archive=$archive"
du -h "$archive"
