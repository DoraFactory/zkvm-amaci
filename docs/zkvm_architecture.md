# zkVM AMACI Target Architecture

The Rust migration should keep all proof business logic in a zkVM-independent core crate, with RISC Zero and SP1 limited to thin input/output adapters.

## Directory boundary

All new migration code and documentation should stay under:

`zkvm-amaci/`

Do not modify existing Circom, SDK, operator, or CosmWasm files during the Rust migration unless a later task explicitly asks for cross-repo integration.

## Workspace layout

```text
zkvm-amaci/
  Cargo.toml
  crates/
    proof-core/
      Cargo.toml
      src/
        lib.rs
        error.rs
        field.rs
        types.rs
        public_output.rs
        execute.rs
        circuits/
          mod.rs
          process_messages.rs
          tally_votes.rs
          process_deactivate.rs
          add_new_key.rs
        crypto.rs
        merkle.rs
        packing.rs
    proof-risc0-guest/
      Cargo.toml
      src/main.rs
    proof-sp1-program/
      Cargo.toml
      src/main.rs
  docs/
    circom_to_rust_migration_map.md
    zkvm_architecture.md
    risc0_sp1_adapter_boundary.md
    testing_plan.md
```

## Core crate responsibilities

`proof-core` owns:

- deterministic data structures for all circuit inputs;
- typed public outputs;
- BN254 field arithmetic compatibility;
- Poseidon/SHA256 field hashing compatibility;
- BabyJubJub ECDH, EdDSA Poseidon verification, and ElGamal logic;
- 5-ary Merkle tree/path verification;
- state transition and tally logic;
- all constraint-equivalent checks.

`proof-core` must not depend on:

- `risc0-zkvm`
- `sp1-zkvm`
- host prover SDKs
- filesystem
- network
- system time
- randomness
- threads or async runtimes

## Initial Rust API shape

The first implementation should model the four top-level circuits explicitly instead of forcing all variants into one untyped struct too early.

```rust
pub enum ProverInput {
    ProcessMessages(ProcessMessagesInput),
    TallyVotes(TallyVotesInput),
    ProcessDeactivate(ProcessDeactivateInput),
    AddNewKey(AddNewKeyInput),
}

pub enum PublicOutput {
    ProcessMessages(ProcessMessagesPublicOutput),
    TallyVotes(TallyVotesPublicOutput),
    ProcessDeactivate(ProcessDeactivatePublicOutput),
    AddNewKey(AddNewKeyPublicOutput),
}

pub fn execute_proof_logic(input: &ProverInput) -> Result<PublicOutput, ProofError>;
```

Each public output should include both:

- the legacy `input_hash` field, preserving Groth16 public-signal equivalence;
- the decompressed semantic fields that were hashed into `inputHash`, in a stable documented order.

## Field representation

Use a dedicated field type instead of raw `u128`/`u256` arithmetic.

Requirements:

- values are canonical modulo BN254 scalar field;
- conversions from decimal string and fixed-width bytes are explicit;
- arithmetic methods make modular behavior obvious;
- range checks for 32-bit, 96-bit, 128-bit, 251-bit, 252-bit, and 253-bit constraints are explicit.

The implementation can start with `num-bigint` or an existing BN254 scalar type to reduce risk. A later no-std pass can replace allocation-heavy dependencies once behavior is pinned by golden tests.

## Public output design

Example shape:

```rust
pub struct ProcessMessagesPublicOutput {
    pub input_hash: Field,
    pub packed_vals: Field,
    pub coord_pub_key_hash: Field,
    pub batch_start_hash: Field,
    pub batch_end_hash: Field,
    pub current_state_commitment: Field,
    pub new_state_commitment: Field,
    pub deactivate_commitment: Field,
    pub expected_poll_id: Field,
}
```

Equivalent structs should exist for the other three circuits. The journal/public-values encoding should be versioned so CosmWasm can later distinguish zkVM outputs from old Groth16 `publicSignals`.

## Error model

Every Circom constraint should map to a structured error:

- `InputHashMismatch`
- `CommitmentMismatch`
- `MerkleRootMismatch`
- `InvalidRange`
- `InvalidBoolean`
- `InvalidSignature`
- `InvalidPollId`
- `InvalidStateTransition`
- `UnsupportedLegacyFixture`
- `BlockingIssue`

Avoid panics in core logic. Guest wrappers may convert an error into `panic!` only at the boundary if the zkVM requires failing execution to reject a proof.

## no_std status

The design should be `alloc`-friendly, but first implementation can use `std` if cryptographic compatibility requires dependencies that are not immediately `no_std`.

Document this in `proof-core/Cargo.toml`:

- default: `std`
- planned feature: `alloc`
- reason if not available: Big integer and Poseidon/BabyJubJub compatibility still under validation.

## Planned files and reasons

| File | Reason |
| --- | --- |
| `zkvm-amaci/Cargo.toml` | Workspace root for core and guest crates. |
| `zkvm-amaci/crates/proof-core/Cargo.toml` | zkVM-independent core crate manifest. |
| `zkvm-amaci/crates/proof-core/src/lib.rs` | Public API exports. |
| `zkvm-amaci/crates/proof-core/src/types.rs` | `ProverInput`, circuit-specific input structs, common state/message types. |
| `zkvm-amaci/crates/proof-core/src/public_output.rs` | Typed `PublicOutput` and stable public field ordering. |
| `zkvm-amaci/crates/proof-core/src/error.rs` | Constraint-equivalent error types. |
| `zkvm-amaci/crates/proof-core/src/field.rs` | BN254 field arithmetic, range checks, serialization helpers. |
| `zkvm-amaci/crates/proof-core/src/packing.rs` | `packElement`, `UnpackElement`, packed public value parsing. |
| `zkvm-amaci/crates/proof-core/src/crypto/*.rs` | Poseidon, SHA256 field hash, BabyJubJub, EdDSA, ECDH, ElGamal, Poseidon decrypt. |
| `zkvm-amaci/crates/proof-core/src/merkle/quin_tree.rs` | 5-ary Merkle roots, paths, zero roots, path-index generation. |
| `zkvm-amaci/crates/proof-core/src/circuits/*.rs` | One Rust module per Circom top-level circuit. |
| `zkvm-amaci/crates/proof-core/src/execute.rs` | Dispatch function `execute_proof_logic`. |
| `zkvm-amaci/crates/proof-risc0-guest/*` | Thin RISC Zero guest wrapper only. |
| `zkvm-amaci/crates/proof-sp1-program/*` | Thin SP1 program wrapper only. |
| `zkvm-amaci/tests/*` | Golden and adapter consistency tests. |

## Current implementation status

Implemented:

- independent `zkvm-amaci` Cargo workspace;
- `proof-core` with typed `ProverInput`, `PublicOutput`, and `execute_proof_logic`;
- latest public input hash reconstruction for all four AMACI circuits;
- commitment, range, boolean, message-chain, Merkle, and packed-value checks;
- `PoseidonDecryptWithoutCheck(7)`, `MessageToCommand`, `MessageValidator`, and `StateLeafTransformer`;
- Circomlib-compatible ElGamal decrypt path for `EscalarMulAny(253)` zero-x behavior;
- full Rust execution paths for `ProcessMessages`, `TallyVotes`, `ProcessDeactivateMessages`, and `AddNewKey`;
- feature-gated RISC0/SP1 read/execute/commit wrappers;
- smoke tests plus golden tests for current `ProcessMessages`, `TallyVotes`, `ProcessDeactivateMessages`, and `AddNewKey` inputs;
- negative mutation tests for hash, commitment, Merkle, message-chain, length/range/boolean, nullifier, and rerandomized-ciphertext failures.

Current intentional limits:

- `proof-core` is `std`/`num-bigint` based, not `no_std`; this keeps cryptographic equivalence auditable first.
- RISC0 is pinned to `risc0-zkvm = 3.0.5`; SP1 is pinned to `sp1-sdk = 6.3.0`, `sp1-build = 6.3.0`, and `sp1-zkvm = 6.3.0`. SP1 builds require the Succinct `succinct` toolchain installed with `sp1up`.
- The Deactivate/AddNewKey fixtures are generated under `zkvm-amaci/tests/golden/` and were checked with manual Circom `--O0` witness verification because Circomkit's default wasm tester path hits a Circom 2.1.9 `--O1` simplification panic for ProcessDeactivate.
- RISC0 host/methods wiring is now present for `process-messages-2-1-5` and `tally-votes-2-1-1`; see `docs/risc0_proving_runbook.md` for setup and run commands. Real local proving for `process-messages-2-1-5` was started successfully but stopped on a low-spec machine before completion.
