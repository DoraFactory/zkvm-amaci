# zkVM Native Optimization Notes

The implementation now keeps a single native backend:

- SHA-256 domain-separated hashes for commitments, message chains, Merkle nodes,
  and public-input hashing.
- Ed25519 command signatures.
- X25519 key agreement for message encryption keys.
- Byte-oriented SHA-256 stream encryption for command payloads.
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
- add separate fixed vote-row types if future circuit sizes use
  `vote_option_tree_depth > 1`;
- add memory/time snapshots for RISC Zero and SP1 after every proof run.
