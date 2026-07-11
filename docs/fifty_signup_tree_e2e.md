# 50-Signup Online + Finalization E2E

## Scenario

This deterministic `3-1-1-5` fixture exercises a realistic round lifecycle:

- 50 initial signups at indices `0..49`;
- states 48 and 49 deactivate while the round is open;
- one replacement key is appended at state index 50;
- 50 vote messages are processed after close;
- 51 final state leaves are tallied in 11 batches;
- expected raw tally: `[10, 20, 27, 36, 50]`.

The depth-3 state tree has capacity `5^3 = 125`. ProcessMessages and Tally keep
their batch size at five.

## Proof Topology

Online proofs, verified immediately:

```text
1 ProcessDeactivate
1 AddNewKey
```

Post-round base proofs:

```text
10 ProcessMessages
11 Tally
```

Post-round recursive proofs:

```text
processMessages: 10 -> [2, 1] = 3 nodes
tally:           11 -> [3, 1] = 4 nodes
finalization root:                1 node
total recursive nodes:            8
```

The proving machine creates 23 base proofs and 8 recursive proofs. The contract
verifies only three proofs: the two online transitions and one Finalization
Root. The online proofs are not recursively verified a second time.

## High-Performance Machine

```bash
cd ~/zkvm-amaci
git fetch origin
git switch aggregation-proof
git pull --ff-only origin aggregation-proof
mkdir -p logs metrics sp1-proofs
```

Run the execute-only preflight first:

```bash
nohup env SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-fifty-target \
  scripts/run_fifty_signup_sp1_preflight.sh \
  > logs/fifty-signup-preflight-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

After `fifty signup SP1 preflight ok`, run the complete proving suite:

```bash
nohup env \
  SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-fifty-target \
  TREE_TARGET_DIR=/tmp/zkvm-amaci-sp1-tree-target \
  scripts/run_fifty_signup_sp1_tree_e2e.sh \
  > logs/fifty-signup-finalization-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

The suite is serial and resumable. Cached base proofs are verified against the
current base program vkey; incompatible cached proofs are regenerated.

Watch progress:

```bash
tail -f $(ls -t logs/fifty-signup-finalization-*.out | head -1)

tail -f $(ls -t \
  logs/sp1-compressed-fifty-signup-*.log \
  logs/sp1-tree-fifty-signup-*.log 2>/dev/null | head -1)
```

Completion markers:

```text
tree finalization build ok
tree finalization proof verify ok
tree finalization suite ok
fifty signup SP1 online + finalization E2E artifacts ready
```

Inspect metrics:

```bash
column -t -s $'\t' \
  $(ls -t metrics/fifty-signup-tree-suite-*.summary.tsv | head -1)

cat $(ls -t metrics/sp1-tree-fifty-signup-*.metrics.txt | head -1)
cat sp1-proofs/fifty-signup-tree/manifest.json
```

## Artifacts to Copy Locally

```text
sp1-proofs/fifty-signup-online-messages.tar.gz
sp1-proofs/fifty-signup-tree-finalization-artifacts.tar.gz
metrics/fifty-signup-tree-suite-*.summary.tsv
metrics/sp1-tree-fifty-signup-*.metrics.txt
metrics/sp1-tree-fifty-signup-*.time.txt
```

The online archive contains only the ProcessDeactivate and AddNewKey CosmWasm
messages. The finalization archive contains:

```text
fifty-signup-tree/contract-config.json
fifty-signup-tree/close-checkpoint.json
fifty-signup-tree/manifest.json
fifty-signup-tree/finalization-root.proof.bytes
fifty-signup-tree/finalization-root.public.bin
fifty-signup-tree/finalization-root.public.json
fifty-signup-tree/finalization-root.vkey.bin
fifty-signup-tree/finalization-root.metrics.json
fifty-signup-tree/finalization-root.verify-compressed.msg.json
```

## Local Chain E2E

```bash
tar -xzf sp1-proofs/fifty-signup-online-messages.tar.gz -C sp1-proofs
tar -xzf sp1-proofs/fifty-signup-tree-finalization-artifacts.tar.gz -C sp1-proofs

npm run build:round-contract

node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifty-signup.tree.example.json
```

The runner performs:

```text
verify ProcessDeactivate
verify AddNewKey
close round and freeze checkpoint
verify Finalization Root
```

Success requires:

```text
phase = finalized
verified_proofs = 3
completed = expected
is_complete = true
```

The checkpoint values in this standalone E2E are exported from the deterministic
fixture. In production they must be read from the canonical AMACI round state at
the close height.
