# AMACI zkVM Testing Plan

Testing must prove semantic equivalence to current Circom before introducing prover-specific complexity.

## Phase 1: Fixture discovery and generation

No committed `public.json` golden files were found during the initial review, but current operator input JSON exists for ProcessMessages and TallyVotes. The Rust tests consume those files directly and use generated fixtures for ProcessDeactivateMessages and AddNewKey.

Required fixture groups:

- `ProcessMessages`
- `TallyVotes`
- `ProcessDeactivateMessages`
- `AddNewKey`
- shared primitives: packing, Poseidon hash wrappers, SHA256 field hash, Merkle paths, EdDSA, ECDH, ElGamal

For future deterministic fixtures, store copies under:

`zkvm-amaci/tests/golden/`

Each fixture should include:

- source circuit name and params;
- JSON input passed to Circom/snarkjs;
- expected `inputHash`;
- decompressed semantic public fields;
- optional witness-derived intermediate values when useful for debugging.

## Phase 2: Core unit tests

Ordinary Rust tests cover the following shared primitive behavior:

- BN254 field add/sub/mul and canonicalization;
- 32-bit/96-bit/128-bit/251-bit/252-bit/253-bit range checks;
- `UnpackElement` high-to-low chunk ordering;
- `packedVals` compatibility with SDK packing for process and tally inputs;
- `Uint32to96` compatibility, including the suspicious `18446744073709552000` constant;
- fixed-width Poseidon hash wrappers used by Merkle, state leaf, and message-chain logic;
- Circom-compatible SHA256 field hash;
- Poseidon decrypt length and nonce validation;
- BabyJubJub ECDH zero-x behavior matching circomlib identity handling;
- EdDSA Poseidon signature verification through circuit-level valid fixtures;
- ElGamal decrypt and rerandomize;
- 5-ary zero roots, path index generation, inclusion roots, and subtree roots.

## Phase 3: Circuit-level golden tests

For each top-level circuit, run `proof-core` against a current Circom input fixture and compare:

- recomputed `inputHash`;
- all semantic public output fields;
- final root/commitment fields;
- expected rejection behavior for invalid inputs where Circom tests currently expect constraint failure.

Minimum tests:

- valid `ProcessMessages` batch;
- invalid `ProcessMessages` poll ID;
- invalid signature causing no state update where the circuit uses sentinel index behavior;
- valid first and non-first `TallyVotes` batch;
- valid `ProcessDeactivateMessages` batch;
- empty deactivate message behavior;
- valid `AddNewKey`;
- invalid `AddNewKey` nullifier or rerandomized ciphertext.

Current implemented golden coverage:

- valid `ProcessMessages` operator fixture with 125-message batch and latest `expectedPollId`;
- valid `TallyVotes` operator fixture with 625 state leaves and 125 vote options.
- valid `ProcessDeactivateMessages` fixture generated from the latest SDK flow and checked with Circom `--O0` plus `snarkjs wtns check`;
- valid `AddNewKey` fixture generated from the latest SDK flow and checked with Circom `--O0` plus `snarkjs wtns check`.
- negative mutation coverage for each top-level circuit:
  - public `inputHash` mismatch;
  - commitment mismatch;
  - message hash-chain mismatch where applicable;
  - Merkle path/root mismatch;
  - length/range/boolean guard failures;
  - AddNewKey nullifier, deactivate leaf, and rerandomized ciphertext failures.

## Phase 4: Wrapper consistency tests

After RISC Zero and SP1 wrappers are added:

- both wrappers call exactly `proof_core::execute_proof_logic`;
- for the same serialized `ProverInput`, both produce byte-identical `PublicOutput`;
- wrapper crates compile without duplicating AMACI logic.

## Phase 5: Optional local proving examples

Only after core golden tests pass:

- RISC Zero local prove + verify example;
- SP1 local prove + verify example.

These examples should remain outside `proof-core` and must not become required for ordinary unit tests unless proving time is acceptable in CI.

## Test blockers

- Current legacy scripts under `packages/circuits/scripts/` are not fully aligned with current AMACI Circom files. Golden fixtures should come from current SDK tests or regenerated current inputgen output.
- Circomkit's wasm tester path currently invokes Circom 2.1.9 in a way that triggers an `--O1` constraint simplification panic for ProcessDeactivate. Manual `--O0` compile and `snarkjs wtns check` passed for the generated fixture.
- RISC0/SP1 feature builds need SDK versions pinned against the project Rust toolchain before adding CI proving checks.
