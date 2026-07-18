# SP1 Post-Round Tree Finalization

This path separates AMACI's online key lifecycle from post-round operator work.
`ProcessDeactivate` and `AddNewKey` proofs are verified while the round is open.
Only the repeated `ProcessMessages` and `Tally` proofs are recursively aggregated
after the round closes.

## Lifecycle

```text
Round open:
  ProcessDeactivate proof -> verify immediately -> update deactivate state
  AddNewKey proof          -> verify immediately -> consume nullifier

Close round:
  freeze state commitment, message range and deactivate commitment

Post-round:
  ProcessMessages proofs -> fan-in-5 stage tree -> processMessages root
  Tally proofs           -> fan-in-5 stage tree -> tally root
                                                -> finalization root
```

The contract therefore performs three proof verifications in the 50-signup
fixture: one online deactivate proof, one online add-new-key proof and one final
post-round proof. It does not re-verify the online proofs inside the final root.

## Online Verification

The contract pins both compressed verifier keys at instantiate time. Callers
cannot supply a replacement vkey in an execute message.

`ProcessDeactivate`:

- must be submitted by the round operator;
- must match the pinned poll ID and coordinator key hash;
- must start from the contract's current deactivate commitment and message hash;
- updates the active and deactivate trees atomically for a valid command;
- treats an invalid, out-of-range, or already-inactive command as a strict tree no-op;
- records the new deactivate root after proof verification.

`AddNewKey`:

- may be submitted by a user or relayer;
- must match the pinned poll ID and coordinator key hash;
- must reference a deactivate root already verified by the contract;
- can only consume a nonzero leaf created by a valid ProcessDeactivate transition;
- consumes a nullifier exactly once.

## Close Checkpoint

Only the configured checkpoint authority can call `close_round`. The standalone
E2E sets it to the operator account; production deployments must configure the
canonical AMACI round contract as the authority. Deactivate/AddNewKey may occur
any number of times while open; their observed counts are frozen at close
together with the ProcessMessages/Tally batch counts. The contract also freezes:

- the initial state commitment for message processing;
- the first and final message-batch hashes;
- the current deactivate commitment derived from online proofs.

In a production AMACI contract, the first three values must come from canonical
on-chain round state. The standalone E2E runner reads deterministic fixture
values from `close-checkpoint.json`.

The verifier contract authenticates the checkpoint source through CosmWasm's
`info.sender`; it does not query an AMACI contract through an assumed external
query schema. In production, the canonical AMACI round contract must send the
`CloseRound` message from its close transition using the values it has just
frozen. Configuring a wallet address as `checkpoint_authority` is a trusted
oracle mode intended only for standalone testing. The deactivate commitment is
never accepted from the close message: it is copied from the verifier
contract's already-verified online state.

## Stage Trees

Each stage uses an independent ordered fan-in-5 tree:

```text
processMessages base proofs -> groups of <= 5 -> ... -> processMessages root
tally base proofs           -> groups of <= 5 -> ... -> tally root
```

Process-message nodes enforce batch-hash, state-commitment, deactivate-
commitment, poll and coordinator continuity. Tally nodes enforce consecutive
batch numbers, a shared state commitment and tally-commitment continuity.

The finalization root verifies exactly two tree children and checks:

- final ProcessMessages state commitment equals the Tally state commitment;
- Tally coverage starts at batch zero and is consecutive;
- ProcessMessages/Tally leaf counts match the round plan;
- its frozen state, message hashes and deactivate commitment match the contract
  checkpoint.

Tree public outputs use the `AMACITR3` codec. V2 `AMACITR2` round-root proofs
are intentionally incompatible with this lifecycle.

## Code Layout

- `crates/proof-core/src/tree_aggregate.rs`: stage-tree and finalization codec,
  ordering checks and checkpoint fields.
- `crates/proof-sp1-tree-program/src/main.rs`: recursive SP1 guest.
- `crates/proof-sp1-tree-host/src/main.rs`: resumable stage-tree scheduler and
  finalization artifact exporter.
- `crates/cosmwasm-amaci-round/src/contract.rs`: online verification,
  checkpoint state machine and finalization verification.
- `scripts/run_sp1_tree_finalization.sh`: generic finalization tree runner.
- `scripts/run_fifty_signup_sp1_tree_e2e.sh`: complete 50-signup proving suite.

## Recursive Shard Benchmark

The tree host defaults to `SHARD_SIZE=16777216` (`2^24`). This is intentionally
different from the `2^23` base-program default. A three-node recursive sample
(one ProcessMessages leaf node, one Tally leaf node and one finalization node)
produced the following results on the 64 GiB CPU prover:

| Shard size | Wall time | Peak RSS (KB) | Final proof bytes |
| ---: | ---: | ---: | ---: |
| 16,777,216 | 3:06.09 | 22,751,440 | 1,272,546 |
| 8,388,608 | 3:05.76 | 27,662,616 | 1,272,546 |
| 4,194,304 | 3:07.60 | 26,172,816 | 1,272,546 |

The smaller shards did not materially improve runtime and increased peak RSS
for this recursive workload. Re-run `scripts/run_sp1_tree_shard_sweep.sh` when
the SP1 version, prover hardware or recursive guest changes.

`TREE_JOBS=2` can build the ProcessMessages and Tally stage trees concurrently.
The finalization node still waits for both stage roots. The default is one job
because two compressed provers may exceed the available memory; the host
rejects values greater than two.

## High-Performance Machine

Run the complete 50-signup suite in the background:

```bash
cd ~/zkvm-amaci
mkdir -p logs metrics sp1-proofs

nohup env \
  SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-fifty-target \
  TREE_TARGET_DIR=/tmp/zkvm-amaci-sp1-tree-target \
  scripts/run_fifty_signup_sp1_tree_e2e.sh \
  > logs/fifty-signup-finalization-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

Completion markers:

```text
tree finalization build ok
tree finalization proof verify ok
tree finalization suite ok
fifty signup SP1 online + finalization E2E artifacts ready
```

Copy both archives to the local repository:

```text
sp1-proofs/fifty-signup-online-messages.tar.gz
sp1-proofs/fifty-signup-tree-finalization-artifacts.tar.gz
```

The first contains the online Deactivate/AddNewKey execute messages. The second
contains the final proof, public values, pinned verifier configuration, close
checkpoint, manifest and CosmWasm execute message.

## Local CosmWasm E2E

```bash
tar -xzf sp1-proofs/fifty-signup-online-messages.tar.gz -C sp1-proofs
tar -xzf sp1-proofs/fifty-signup-tree-finalization-artifacts.tar.gz -C sp1-proofs

npm run build:round-contract

node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifty-signup.tree.example.json
```

A successful query reports:

```text
phase: finalized
completed.process_deactivate: 1
completed.add_new_key: 1
completed.process_messages: 10
completed.tally: 11
verified_proofs: 3
is_complete: true
```

The transaction sequence is:

```text
store code
instantiate
verify online ProcessDeactivate
verify online AddNewKey
close round
verify Finalization Root
```

## Finalization Artifacts

```text
sp1-proofs/fifty-signup-tree/contract-config.json
sp1-proofs/fifty-signup-tree/close-checkpoint.json
sp1-proofs/fifty-signup-tree/manifest.json
sp1-proofs/fifty-signup-tree/finalization-root.proof.bytes
sp1-proofs/fifty-signup-tree/finalization-root.public.bin
sp1-proofs/fifty-signup-tree/finalization-root.public.json
sp1-proofs/fifty-signup-tree/finalization-root.vkey.bin
sp1-proofs/fifty-signup-tree/finalization-root.metrics.json
sp1-proofs/fifty-signup-tree/finalization-root.verify-compressed.msg.json
```

The final compressed proof remains fixed-size. The primary benefit is reducing
21 post-round verifier calls (10 ProcessMessages and 11 Tally) to one while
preserving immediate online key lifecycle updates.
