# zkVM Native Optimization Notes

The implementation now keeps a single native backend:

- SHA-256 domain-separated hashes for commitments, message chains, Merkle nodes,
  and public-input hashing.
- ML-DSA-65 command signatures.
- ML-KEM-768 key encapsulation for message encryption keys and key replacement.
- Byte-oriented SHA-256 stream encryption with a domain-separated HMAC-SHA256 ciphertext tag.
- Native `Digest = [u8; 32]` and `NativeCommand` types for canonical command
  signing messages.

Completed fixed-layout refactor:

- hot-path field values use fixed-width `U256` instead of heap-backed bigints;
- public outputs are native `[u8; 32]` digests;
- messages are fixed `[Field; 10]` values;
- state leaves are fixed `[Field; 10]` values;
- tally vote rows are fixed `[Field; 5]` for the current `2-1-1-5` scale;
- quin Merkle path siblings are fixed `[Field; 4]` values;
- hash and Merkle code serializes field words as canonical 32-byte big-endian
  data before hashing.
- RISC Zero and SP1 private inputs use a shared compact byte codec instead of
  serde-decoding `ProverInput` in the guest.
- RISC Zero and SP1 public outputs use the same compact byte codec and are
  committed as raw fixed bytes instead of serde-encoding `PublicOutput` in the
  guest journal.
- Merkle inclusion/root checks have digest-native APIs and only convert to
  `Field` at protocol boundaries that still store roots as field words.
- `scripts/run_bench.sh` captures prove/verify or execute logs, `/usr/bin/time
  -v` memory/time data, proof artifact sizes, public JSON sizes, and public
  output compare status.

Removed components:

- alternate crypto backend features;
- vendored curve/hash helper crates that are not used by the native backend;
- fixture files and generator scripts for the removed compatibility path;
- stale documents for the removed compatibility path.

Current optimization targets still worth measuring:

- measure proof memory and time after the fixed-width `U256` / `[u8; 32]`
  public-output and compact journal refactor;
- use `scripts/run_sp1_profile_suite.sh` to capture native, SP1 execute, and
  compressed-proof metrics for every hot AMACI stage before adding recursion;
- prioritize `processMessages` and `tally`, because their proof count grows with
  message and signup volume;
- add separate fixed vote-row types if future circuit sizes use
  `vote_option_tree_depth > 1`;
- add memory/time snapshots for RISC Zero and SP1 after every proof run.

Completed follow-up optimization:

- `processMessages` now rolls a single `next_state_root` through the reverse
  batch loop instead of allocating a `batch_size + 1` vector of intermediate
  roots.
- `processMessages` uses a fixed decrypt output for the native command payload
  and returns early for invalid/no-op messages after required witness checks.
- `processDeactivate` skips empty slots instead of walking dummy Merkle paths.

## Native Protocol Semantics

The native zkVM protocol intentionally no longer emulates Circom's BN254,
BabyJubJub, Poseidon, or ElGamal arithmetic. It preserves the AMACI state
transition structure while using ML-DSA-65, ML-KEM-768, SHA-256 and checked
`U256` integer arithmetic. In particular:

- the active-state tree is the sole authority for whether a key is inactive;
- a valid deactivate command updates the active and deactivate trees atomically;
- an invalid, out-of-range, already-inactive, or unauthenticated deactivate
  command is a strict no-op and cannot create a leaf consumable by `AddNewKey`;
- authenticated decryption uses a domain-separated HMAC-SHA256 tag; tag failure
  makes that queue item a no-op without aborting the rest of the batch;
- command state indices are zero-based, and balances and tally arithmetic reject
  overflow or underflow instead of wrapping or saturating.

These changes alter the guest program identity and proof artifacts. Existing
SP1 vkeys/proofs, RISC Zero image IDs/receipts, recursive tree nodes and deployed
verifier configuration must be regenerated before the next E2E run.
