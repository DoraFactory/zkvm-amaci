# 50-Signup Tree Aggregation E2E

## Purpose

This fixture is the first benchmark large enough to exercise multiple
fan-in-5 aggregation groups for both repeated AMACI stages while remaining
practical to prove sequentially on one high-memory machine.

The circuit shape is `3-1-1-5`, not `2-1-1-5`:

- state tree depth 3 gives `5^3 = 125` state-leaf capacity;
- internal state tree depth remains 1, so each tally proof handles 5 leaves;
- vote-option tree depth remains 1;
- each process-message proof handles 5 messages.

## Deterministic Round Data

- 50 initial signups at state indices `0..49`;
- states 48 and 49 are deactivated;
- one replacement key is appended at state index 50;
- state 47 abstains;
- states `0..46` submit one valid vote each;
- deactivated states 48 and 49 each submit one invalid old-key vote;
- replacement state 50 submits one valid option-4 vote with weight 5.

For valid original users:

```text
vote_option = state_index % 5
vote_weight = vote_option + 1
```

The expected raw result is:

```text
[10, 20, 27, 36, 50]
```

This result, every compact input round-trip, all 23 native stage executions and
all inter-stage commitments are covered by `core_smoke` tests before proving.

## Proof Counts

Base proofs:

| Stage | Items | Base proofs |
| --- | ---: | ---: |
| ProcessDeactivate | 2 deactivations | 1 |
| AddNewKey | 1 replacement | 1 |
| ProcessMessages | 50 messages | 10 |
| Tally | 51 final leaves | 11 |
| Total | | 23 |

Recursive proofs:

```text
processMessages: 10 -> [2, 1] = 3 recursive nodes
tally:           11 -> [3, 1] = 4 recursive nodes
final round root:               1 recursive node
total:                          8 recursive nodes
```

The proving machine therefore creates 31 proofs in total, sequentially. The
CosmWasm tree path verifies only the final round-root proof.

## High-Performance Machine

Install the normal SP1 dependencies and select the `aggregation-proof` branch.
Because the previous PQC process-message proof was close to the 64 GiB machine
limit, prepare the repository and output directories first:

```bash
cd ~/zkvm-amaci
git fetch origin
git switch aggregation-proof
git pull --ff-only origin aggregation-proof
mkdir -p logs metrics sp1-proofs
```

Then run an SP1 execute preflight. It does not generate proofs:

```bash
nohup env SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-fifty-target \
  scripts/run_fifty_signup_sp1_preflight.sh \
  > logs/fifty-signup-preflight-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

After `fifty signup SP1 preflight ok`, inspect:

```bash
column -t -s $'\t' \
  $(ls -t metrics/fifty-signup-preflight-*.summary.tsv | head -1)
```

Then start the complete base-proof and tree run in the background:

```bash
nohup env \
  SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-fifty-target \
  TREE_TARGET_DIR=/tmp/zkvm-amaci-sp1-tree-target \
  scripts/run_fifty_signup_sp1_tree_e2e.sh \
  > logs/fifty-signup-tree-e2e-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

The script runs one prover at a time. Re-running the same command verifies and
reuses completed base artifacts. Recursive tree nodes are also verified and
reused. Set `FORCE_REPROVE=1` only when every base proof must be regenerated.

Watch the overall workflow and the currently active proof:

```bash
tail -f $(ls -t logs/fifty-signup-tree-e2e-*.out | head -1)

tail -f $(ls -t \
  logs/sp1-compressed-fifty-signup-*.log \
  logs/sp1-tree-fifty-signup-*.log 2>/dev/null | head -1)
```

Check whether a prover is active:

```bash
pgrep -af 'amaci-proof-sp1|sp1-prover'
```

Completion markers:

```text
tree round build ok
tree round proof verify ok
tree round suite ok
fifty signup SP1 tree E2E artifacts ready
```

Inspect the latest summary:

```bash
column -t -s $'\t' \
  $(ls -t metrics/fifty-signup-tree-suite-*.summary.tsv | head -1)

cat $(ls -t metrics/sp1-tree-fifty-signup-*.metrics.txt | head -1)
cat sp1-proofs/fifty-signup-tree/manifest.json
```

## Artifacts to Copy Locally

```text
sp1-proofs/fifty-signup-base-messages.tar.gz
sp1-proofs/fifty-signup-tree-round-artifacts.tar.gz
metrics/fifty-signup-tree-suite-*.summary.tsv
metrics/sp1-tree-fifty-signup-*.metrics.txt
metrics/sp1-tree-fifty-signup-*.time.txt
```

The base archive contains 23 CosmWasm execute messages for the non-aggregate
comparison. The tree archive contains the final proof/public/vkey triplet,
contract configuration, execute message and tree manifest.

## Local Chain Comparison

Extract both archives from the repository root:

```bash
tar -xzf sp1-proofs/fifty-signup-base-messages.tar.gz -C sp1-proofs
tar -xzf sp1-proofs/fifty-signup-tree-round-artifacts.tar.gz -C sp1-proofs
```

Build the contract, then run the two E2E manifests independently:

```bash
npm run build:round-contract

node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifty-signup.example.json

node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifty-signup.tree.example.json
```

The non-aggregate result must report `verified_proofs = 23`. The tree result
must report the same completed stage counts with `verified_proofs = 1`. Compare
their generated `summary.json` files for total gas, estimated DORA and proof
message bytes.
