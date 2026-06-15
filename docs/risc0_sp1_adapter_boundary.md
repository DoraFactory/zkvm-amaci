# RISC Zero and SP1 Adapter Boundary

The core rule is strict: all AMACI business logic lives in `proof-core`; RISC Zero and SP1 crates only adapt their guest IO APIs to the shared core API.

## Shared code

Shared by RISC Zero, SP1, and ordinary unit tests:

- `ProverInput`
- `PublicOutput`
- core proof logic
- BN254 field arithmetic
- Poseidon hashing
- SHA256 field hashing
- BabyJubJub ECDH/signature/ElGamal logic
- 5-ary Merkle tree logic
- state transition logic
- tally logic
- serialization rules
- golden tests

## RISC Zero-only code

Allowed in `proof-risc0-guest`:

- RISC Zero guest env read
- RISC Zero guest journal commit
- panic/error conversion appropriate for guest failure

RISC Zero host-side work, when added later:

- RISC Zero image ID
- RISC Zero receipt/seal
- RISC Zero host prover
- RISC Zero local verifier

Not allowed in RISC Zero wrapper:

- hashing implementation
- Merkle implementation
- state transition logic
- AMACI validation rules
- public output field ordering decisions

Implemented wrapper shape:

```rust
fn main() {
    let input: amaci_proof_core::ProverInput = risc0_zkvm::guest::env::read();
    let output = amaci_proof_core::execute_proof_logic(&input)
        .expect("AMACI proof logic failed");
    risc0_zkvm::guest::env::commit(&output);
}
```

The source code is feature-gated behind `risc0`. The manifest does not pin `risc0-zkvm` yet; choose a project-compatible SDK/toolchain before enabling that feature in CI.

## SP1-only code

Allowed in `proof-sp1-program`:

- SP1 input read
- SP1 public values commit
- panic/error conversion appropriate for guest failure

SP1 host-side work, when added later:

- SP1 ELF / verifying key
- SP1 proof types
- SP1 host prover
- SP1 local verifier

Not allowed in SP1 wrapper:

- hashing implementation
- Merkle implementation
- state transition logic
- AMACI validation rules
- public output field ordering decisions

Implemented wrapper shape:

```rust
fn main() {
    let input = sp1_zkvm::io::read::<amaci_proof_core::ProverInput>();
    let output = amaci_proof_core::execute_proof_logic(&input)
        .expect("AMACI proof logic failed");
    sp1_zkvm::io::commit(&output);
}
```

The source code is feature-gated behind `sp1`. The manifest does not pin `sp1-zkvm` yet; choose a project-compatible SDK/toolchain before enabling that feature in CI.

## Serialization boundary

Use one canonical serialization format for `ProverInput` and `PublicOutput` in `proof-core`.

Requirements:

- deterministic;
- no map-order dependence;
- decimal-string fixture support for compatibility with current Circom input JSON;
- binary encoding support for guest IO;
- versioned public output encoding.

Current path:

- `ProverInput` and `PublicOutput` derive Serde for JSON fixtures and guest IO compatibility;
- operator golden tests use decimal-string JSON conversion;
- binary guest IO encoding is delegated to each selected zkVM SDK read/commit API;
- public field order is represented by typed structs and documented in `circom_to_rust_migration_map.md`.

## On-chain future work

Do not implement this in the first Rust core phase.

Later CosmWasm work must decide:

- CosmWasm verifier
- proof bytes format
- public output encoding
- gas benchmark
- Groth16/PLONK wrapped proof vs native STARK proof
- whether `inputHash` remains the only contract-facing public value or whether typed zkVM public outputs are consumed directly
