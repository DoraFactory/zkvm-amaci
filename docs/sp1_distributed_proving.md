# SP1 distributed child proving

The `9-3-1-5` hundred-user round can be proved as an immutable, resumable
three-stage pipeline. This changes prover orchestration only. AMACI state
transitions, PQC authentication/KEM, public outputs, compressed proof format,
and the fan-in-5 finalization tree are unchanged.

```text
prepare-witnesses
    |
    +-- manifest.json + checksums.sha256
    +-- 23 canonical binary inputs
    +-- 23 expected public outputs
    |
build-worker-bundle           (coordinator only)
    |
    +-- one base host + one tree host
    +-- matched program vkeys + binary checksums
    |
    v
prove-child --index N       (independent workers)
    |
    +-- 2 online proofs
    +-- 20 ProcessMessages proofs
    +-- 1 Tally proof
    |
    v
aggregate-finalization
    |
    +-- PM tree [4, 1]
    +-- Tally tree [1]
    +-- Finalization root
```

## Trust boundary

`prepare-witnesses` executes the native proof logic once and exports each
`ProverInput` with the proof-core canonical binary codec. It also exports the
exact expected public bytes. `checksums.sha256` covers the manifest, task list,
all inputs, and all expected outputs.

Record the printed witness and worker-bundle SHA-256 values outside the worker
packages. Workers reject modified inputs and modified host binaries before
proving. A completed child is accepted only when:

1. Its result references the same pipeline checksum.
2. Its artifact checksums pass.
3. Its public bytes equal the frozen expected public bytes.
4. The SP1 compressed verifier accepts it.
5. Its vkey matches every other child before aggregation.
6. Its vkey belongs to the base program embedded in the coordinator's tree host.

The final tree host verifies every child proof again recursively. Therefore a
worker cannot replace a valid transition with an arbitrary public output.

The worker host must not be rebuilt independently on each machine. SP1 embeds
the guest ELF into the host; the ELF and its vkey can differ when the same source
is built from different checkout paths. `build-worker-bundle` builds the base
and tree hosts together, checks both views of the base program vkey, and ships
those exact binaries. This is a reproducibility requirement, not a protocol
change.

## Task indexes

Indexes are zero based and deterministic:

| Index | Stage |
| ---: | --- |
| `0` | ProcessDeactivate |
| `1` | AddNewKey |
| `2..21` | ProcessMessages batches `0..19` |
| `22` | Tally batch `0` |

The exact mapping is always available in `WORK_DIR/tasks.tsv`.

## Coordinator: prepare

```bash
cd ~/zkvm-amaci
mkdir -p logs

scripts/run_sp1_distributed_pipeline.sh prepare-witnesses

stamp=$(date +%Y%m%d-%H%M%S)
nohup env \
  SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-hundred-9315-target \
  TREE_TARGET_DIR=/tmp/zkvm-amaci-sp1-hundred-tree-target \
  scripts/run_sp1_distributed_pipeline.sh build-worker-bundle \
  > "logs/sp1-worker-bundle-${stamp}.out" 2>&1 &
```

The default work directory is:

```text
sp1-work/hundred-signup-9-3-1-5
```

The two commands create these portable packages:

```text
sp1-work/hundred-signup-9-3-1-5-witnesses.tar.gz
sp1-work/hundred-signup-9-3-1-5-worker-bundle.tar.gz
```

Wait for `build worker bundle ok`, then record both archive SHA-256 values. The
bundle contains the paired `amaci-proof-sp1-host` and
`amaci-proof-sp1-tree-host` Linux binaries plus their individual checksums.

Before distributing them, verify the recorded archive digests. After extracting
the binary bundle, its internal manifest can be checked independently:

```bash
sha256sum sp1-work/hundred-signup-9-3-1-5-{witnesses,worker-bundle}.tar.gz

cd sp1-work/hundred-signup-9-3-1-5/worker-bundle
sha256sum -c bundle-checksums.sha256
cd -
```

## Worker: prove one child

Extract the same witness and binary packages on every worker. Workers must have
the same CPU architecture and a compatible Linux/glibc runtime as the
coordinator. Keep the printed archive checksums as external reference values.

```bash
mkdir -p sp1-work/hundred-signup-9-3-1-5
tar -xzf sp1-work/hundred-signup-9-3-1-5-witnesses.tar.gz \
  -C sp1-work/hundred-signup-9-3-1-5
tar -xzf sp1-work/hundred-signup-9-3-1-5-worker-bundle.tar.gz \
  -C sp1-work/hundred-signup-9-3-1-5

work="$PWD/sp1-work/hundred-signup-9-3-1-5"
nohup env \
  SP1_HOST_BINARY="$work/worker-bundle/amaci-proof-sp1-host" \
  scripts/run_sp1_distributed_pipeline.sh prove-child --index 2 \
  > logs/sp1-child-00002-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

After success, the worker emits:

```text
sp1-work/hundred-signup-9-3-1-5/packages/child-00002.tar.gz
```

On a 64 GiB host, run only one ProcessMessages worker at a time because the
current `2^23` shard profile peaks near 61 GiB. A machine can process a list
sequentially:

```bash
for index in 2 6 10 14 18; do
  env SP1_HOST_BINARY="$work/worker-bundle/amaci-proof-sp1-host" \
    scripts/run_sp1_distributed_pipeline.sh prove-child --index "$index"
done
```

Different machines can use disjoint lists. Proof generation is independent
after the inputs have been frozen, even though the public state commitments in
the manifest remain sequentially linked.

## Coordinator: collect and inspect

Copy every worker `child-*.tar.gz` package into a coordinator directory, then
extract it into the pipeline root:

```bash
work=sp1-work/hundred-signup-9-3-1-5
for package in collected/child-*.tar.gz; do
  tar -xzf "$package" -C "$work"
done

scripts/run_sp1_distributed_pipeline.sh status
```

Expected status before finalization:

```text
ready=23
missing_or_invalid=0
```

When the worker bundle is present, `status` also checks every child vkey against
that bundle. A child from another build is shown as `incompatible-vkey` and is
not counted as ready.

Re-running `prove-child` for a valid task verifies and resumes it instead of
proving it again. Concurrent attempts for the same task are rejected by an
atomic task lock. Repackaging an unchanged child is deterministic: repeated
resume runs produce the same package SHA-256.

## Coordinator: aggregate

```bash
stamp=$(date +%Y%m%d-%H%M%S)
work="$PWD/sp1-work/hundred-signup-9-3-1-5"
nohup env \
  SP1_HOST_BINARY="$work/worker-bundle/amaci-proof-sp1-host" \
  TREE_HOST_BINARY="$work/worker-bundle/amaci-proof-sp1-tree-host" \
  scripts/run_sp1_distributed_pipeline.sh aggregate-finalization \
  > "logs/sp1-distributed-finalization-${stamp}.out" 2>&1 &
```

The final contract artifacts and metrics are written to:

```text
sp1-work/hundred-signup-9-3-1-5/finalization-artifacts.tar.gz
sp1-work/hundred-signup-9-3-1-5/finalization-tree/
sp1-work/hundred-signup-9-3-1-5/aggregation/finalization.metrics.txt
```

The tree output remains one approximately 1.27 MB compressed proof. The
ProcessDeactivate and AddNewKey proofs remain separate online proofs.

## Local checks

The control-plane tests do not generate SP1 proofs:

```bash
cargo test -p amaci-proof-core --bin export_hundred_signup_pipeline
cargo test -p amaci-proof-sp1-host
scripts/test_sp1_distributed_pipeline.sh
```

They cover deterministic export, canonical input loading, checksum tampering,
unknown task indexes, duplicate task locks, prepare resume, and rejection of
premature aggregation.
