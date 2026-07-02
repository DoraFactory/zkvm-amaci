# SP1 Pre-Aggregation Optimization Plan

This is the current optimization order before implementing recursive proof
aggregation for AMACI batches.

## Priority 1: Profile the Hot Paths

Run the profiling suite before and after every optimization:

```bash
nohup env NATIVE_ITERS=200 \
  scripts/run_sp1_profile_suite.sh execute \
  > logs/sp1-profile-execute-$(date +%Y%m%d-%H%M%S).out 2>&1 &

nohup env NATIVE_ITERS=200 \
  scripts/run_sp1_profile_suite.sh compressed \
  > logs/sp1-profile-compressed-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Record:

- `avg_execute_ms` from native `proof-core`;
- SP1 `instructions`, `syscalls`, and `touched_memory_addresses`;
- `/usr/bin/time -v` `max_rss_kbytes`;
- `input_bytes`, `public_values_bytes`, and compressed proof byte sizes.

The default suite covers:

- `five-signup-process-deactivate`
- `five-signup-add-new-key`
- `five-signup-process-messages-full`
- `five-signup-tally-0`
- `five-signup-tally-1`

## Priority 2: Optimize ProcessMessages

`processMessages` scales with message count and is the first aggregation target.
Current low-risk optimization completed:

- removed the `state_roots` vector allocation in the reverse batch loop and
  replaced it with a rolling `next_state_root`.
- changed process-message command decrypt in the hot path to a fixed
  `[Field; 9]` output instead of allocating a `Vec<Field>`.
- short-circuits invalid/no-op messages after required witness checks, avoiding
  the new vote-root and new state-leaf Merkle recomputation when the state does
  not change.

Next candidates:

- avoid remaining temporary `Vec` allocations in command decrypt/validation;
- reduce repeated field-to-digest conversions in Merkle checks;
- keep command/public-key/state-leaf data as fixed arrays through the hot path;
- audit that all SHA-256 calls use the SP1 patched/precompile path.

## Priority 3: Optimize Tally

`tally` scales with signup/state leaf count.

Next candidates:

- make current tally results fixed `[Field; 5]` internally even if the external
  input type remains `Vec<Field>`;
- avoid `check_root` heap buffers for the fixed 5-leaf vote option tree;
- avoid rebuilding zero roots and fixed empty vote rows inside repeated batches.

## Priority 4: Revisit Batch Size

The current compatibility scale processes 5 messages or 5 state leaves per
proof. zkVM does not require that exact batch size. After profiling is stable,
measure larger batch fixtures:

- processMessages batch size 5, 10, 20;
- tally batch size 5, 10, 20.

If the proving cost grows sublinearly, larger batches reduce the number of
batch proofs before aggregation.

## Priority 5: Aggregation

After single-batch cost is stable, aggregate by repeated stage:

- aggregate all `processMessages_*` proofs into one process-message aggregate;
- aggregate all `tally_*` proofs into one tally aggregate;
- optionally aggregate the round-level proofs into one final round proof.

The aggregation proof must check internal chaining:

- processMessages batch hashes and state commitments are contiguous;
- tally commitments and batch numbers are contiguous;
- final aggregate outputs match the round-level public commitments.

## Current Branch Notes

The `improve-proof` branch also skips empty slots in `processDeactivate`. Empty
slots do not change active or deactivate roots, so the zkVM-friendly execution
can avoid proving dummy state, active, and deactivate Merkle paths for those
slots.
