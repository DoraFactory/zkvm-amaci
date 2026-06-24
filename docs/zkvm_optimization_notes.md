# zkVM Optimization Notes

This document tracks optimizations for two execution modes:

- default mode keeps Rust circuit semantics aligned with the Circom golden
  outputs;
- `zkvm-native-crypto` mode keeps the AMACI protocol flow but switches
  circuit-level commitments, Merkle hashing, message chains, and public input
  hashing to SHA-256 based field hashes.

## Implemented

### Circom-Compatible Mode

- Poseidon padding now converts directly into field elements instead of cloning
  and padding `BigUint` vectors first.
- Small fixed-arity Poseidon callers use reference-based helpers where possible,
  avoiding temporary heap vectors for two-input hashes.
- SHA-256 uint256 packing now left-pads into a fixed 32-byte buffer instead of
  repeatedly inserting at the front of a `Vec<u8>`.
- Quin-tree zero roots are cached per process, so repeated `zero_root(depth)`
  calls no longer recompute the same Poseidon chain.
- Merkle path hashing and `MessageHasher` use fixed arrays instead of allocating
  a new vector on each level/message.
- BabyJubJub fixed constants, ElGamal scalar bounds, and field inverse exponent
  are cached instead of reconstructed in hot paths.
- Scalar bit extraction uses `BigUint::bit()` instead of allocating shifted
  temporary values for every bit.
- `ProcessMessages` max vote weight is cached instead of decimal-parsed during
  each message validation.

### zkVM-Native Crypto Mode

- Added a `zkvm-native-crypto` feature to `proof-core`, RISC Zero host/methods,
  RISC Zero guest, SP1 host, and SP1 program.
- Added a single `hash_backend` boundary for protocol-level hash operations.
- In native mode, protocol-level hashes use domain-separated SHA-256 with
  explicit arity encoding and uint256 serialization. Native SHA-256 outputs are
  preserved as full 256-bit values instead of being reduced into the BN254
  scalar field.
- In native mode, coordinator/user public keys are encoded as
  `[Ed25519 verifying key, X25519 public key]`.
- In native mode, command signatures are Ed25519 signatures split across
  `sig_r8[0]`, `sig_r8[1]`, and `sig_s` as 22/21/21-byte chunks.
- In native mode, shared keys are derived with X25519 rather than BabyJubJub
  scalar multiplication.
- In native mode, `poseidon_decrypt_without_check` is replaced by a SHA-256
  keystream decrypt helper. A matching native encryption helper is available for
  tests and future witness generation.
- Native mode is wired into host built-in inputs, RISC Zero guest method builds,
  and SP1 program builds, so host and guest use the same backend.
- Added a non-empty native `ProcessMessages` sample input
  (`process-messages-native-1-1`) that exercises Ed25519 command signature
  verification, X25519 shared key derivation, SHA-256 keystream decryption,
  message chain hashing, and a real state leaf update.
- RISC Zero native mode was smoke-tested in dev mode for the non-empty
  `process-messages-native-1-1` input.
- Native `hash_pair` now hashes borrowed field references directly instead of
  cloning both inputs before every pair hash.
- Native stream encryption/decryption precomputes the SHA-256 stream prefix once
  per message and only appends the word index inside the loop.
- Native public keys now keep their full 32-byte Ed25519/X25519 values and the
  native message stream cipher uses byte-wise XOR. This removes the previous
  rejection-sampling loop that searched for public keys below the BN254 scalar
  field, while preserving exact encrypted payload round trips.
- Native Ed25519 command signing now hashes structured command bytes directly,
  instead of first converting the command through the protocol field-hash API.
- Added backend-specific Cargo config files for patched SHA-256 and
  Curve25519:
  - `configs/cargo-risc0-native-patches.toml`
  - `configs/cargo-sp1-native-patches.toml`
- Added a `process-messages-native-2-1-5` built-in sample input. It uses a
  real two-level state tree, one valid native message, four empty batch slots,
  and generated 5-ary Merkle paths for both the valid state leaf and the empty
  fallback leaf.
- Added `native_profile`, a lightweight release-mode `proof-core` profiler for
  measuring input construction and repeated `execute_proof_logic` calls without
  running zkVM proof generation.
- Added an SP1 host `execute` command that runs the guest without proof
  generation, checks guest public values against host-side `proof-core`, and
  prints instruction, syscall, touched-memory, and gas metrics.

## Current Local Baselines

On the local development machine:

- `native_profile process-messages-native-2-1-5 --iters 20`:
  - input construction: about 0.46 ms;
  - average `execute_proof_logic`: about 0.22 ms.
- SP1 `execute process-messages-native-2-1-5`:
  - instructions: 4,164,679;
  - syscalls: 0;
  - normalized gas: 3,993,313.

## Not Changed Yet

- The core field representation is still `BigUint`. A larger optimization pass
  should replace hot arithmetic with fixed-width limb types.
- Native mode still keeps the existing high-level message format and state
  transition flow. Production witness generation must use the native
  Ed25519/X25519/SHA helpers rather than Circom Poseidon/BabyJubJub tooling.
- The workspace does not globally patch `sha2` or `curve25519-dalek` because
  RISC Zero and SP1 use different patched-crate sources. Use the backend-specific
  Cargo config files when building a single zkVM target.

## Next Candidates

- Run real proving baselines with the backend-specific patched crate configs on
  the high-performance machine.
- Add RISC Zero `RISC0_INFO=1` logs for `process-messages-native-2-1-5` to
  confirm SHA/Curve25519 precompile usage.
- Rewrite `Field` hot paths from `BigUint` to a fixed-width scalar type.
- Replace `scalar_mul_any_253_circom` bit-vector allocation with segmented bit
  access over the scalar.
- Precompute Montgomery BabyJubJub constants (`curve_a`, `curve_b`) once.
- Add guest-side cycle reports for RISC Zero (`RISC0_INFO=1`) and SP1 profiling
  before deeper rewrites.
