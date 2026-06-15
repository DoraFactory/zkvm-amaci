# AMACI Circom to Rust Migration Map

This document maps the current AMACI Circom proof logic to the Rust logic under `zkvm-amaci` and the thin RISC Zero/SP1 guest wrappers.

Scope reviewed:

- `packages/circuits/circom/amaci/power/*.circom`
- shared Circom utilities under `packages/circuits/circom/utils/`
- current circuit registry in `packages/circuits/circom/circuits.json`
- current TypeScript/Rust input generation paths in `packages/sdk/src/operator.ts`, `packages/sdk/src/libs/crypto/*`, and `crates/maci-inputgen/src/msg_tally.rs`
- legacy scripts under `packages/circuits/scripts/`

## Top-level AMACI circuits

| Circuit | File | Params in `circuits.json` | Public signals | Purpose |
| --- | --- | --- | --- | --- |
| `ProcessMessages` | `amaci/power/processMessages.circom` | `[2, 1, 5]` | `inputHash` | Proves a batch of encrypted vote messages was included in the message hash chain, decrypted with the coordinator key, validated, and applied to the state tree. |
| `TallyVotes` | `amaci/power/tallyVotes.circom` | `[2, 1, 1]` | `inputHash` | Proves one tally batch over a state subtree and updates the tally commitment. |
| `ProcessDeactivateMessages` | `amaci/power/processDeactivate.circom` | `[2, 5]` | `inputHash` | Proves a batch of deactivate messages was included, decrypted/validated, and applied to active-state and deactivate trees. |
| `AddNewKey` | `amaci/power/addNewKey.circom` | `[2]` | `inputHash` | Proves a voter knows an old key corresponding to a deactivate leaf, creates a round nullifier, rerandomizes the deactivate ciphertext, and binds the new public key. |

The Groth16 public signal list is currently only `["inputHash"]` for each AMACI circuit. The values hashed into `inputHash` are semantically public and must become typed fields in Rust `PublicOutput`; the zkVM journal/public-values encoding should commit these fields in a stable order rather than expose an anonymous one-element array.

## Public values compressed into `inputHash`

`inputHash` is SHA256 over ABI-style `uint256` values, reduced modulo the BN254 scalar field:

`inputHash = uint256(sha256(abi_uint256_values)) mod SNARK_FIELD_SIZE`

The Circom `Sha256Hasher` implementation converts each field element with `Num2Bits(256)`, reverses bits into SHA256, then reverses SHA256 output into a field element. Rust must match this exactly. Do not replace it blindly with hashing decimal strings or little-endian byte arrays.

### ProcessMessages input hash

From `ProcessMessagesInputHasher`:

1. `packedVals`
2. `poseidon(coordPubKey[0], coordPubKey[1])`
3. `batchStartHash`
4. `batchEndHash`
5. `currentStateCommitment`
6. `newStateCommitment`
7. `deactivateCommitment`
8. `expectedPollId`

`packedVals` is unpacked as:

- `maxVoteOptions = bits[0..31]`
- `numSignUps = bits[32..63]`
- `isQuadraticCost = bits[64..95]`

The SDK constructs it as:

`maxVoteOptions + (numSignUps << 32) + (isQuadraticCost ? 1 << 64 : 0)`

This is intentionally inverted by `UnpackElement(3)`, whose outputs are high-to-low 32-bit chunks.

### TallyVotes input hash

From `TallyVotesInputHasher`:

1. `packedVals`
2. `stateCommitment`
3. `currentTallyCommitment`
4. `newTallyCommitment`

`packedVals = batchNum + (numSignUps << 32)`, unpacked as:

- `batchNum = out[1]`
- `numSignUps = out[0]`

### ProcessDeactivateMessages input hash

From `ProcessDeactivateMessagesInputHasher`:

1. `newDeactivateRoot`
2. `poseidon(coordPubKey[0], coordPubKey[1])`
3. `batchStartHash`
4. `batchEndHash`
5. `currentDeactivateCommitment`
6. `newDeactivateCommitment`
7. `currentStateRoot`
8. `expectedPollId`

### AddNewKey input hash

From `AddNewKeyInputHasher`:

1. `deactivateRoot`
2. `poseidon(coordPubKey[0], coordPubKey[1])`
3. `nullifier`
4. `d1[0]`
5. `d1[1]`
6. `d2[0]`
7. `d2[1]`
8. `poseidon(newPubKey[0], newPubKey[1])`
9. `pollId`

## Main private witness inputs

All top-level signal inputs other than `inputHash` are private witness from the Groth16 perspective, even when they represent public contract data. For zkVM migration, split them into:

- public-output source fields: the values that must be journaled and verified on-chain;
- private witness fields: coordinator key material, messages, Merkle paths, state leaves, salts, vote arrays, ciphertext randomness, and intermediate leaves.

### ProcessMessages private witness

- coordinator private key and public key
- encrypted messages `msgs[batchSize][10]`
- message encryption public keys `encPubKeys[batchSize][2]`
- current state root, state leaves, and state Merkle paths
- current/new state commitments and salts
- active-state root, deactivate root, deactivate commitment
- active-state leaves and active-state paths
- current vote weights and vote-option tree paths
- `batchStartHash`, `batchEndHash`, `packedVals`, `expectedPollId`

### TallyVotes private witness

- state root and salt
- state leaves for the current tally batch
- path from state subtree root to state root
- per-user vote arrays
- current results, current results salt, new results salt
- `packedVals`, current/new tally commitments

### ProcessDeactivateMessages private witness

- current active-state root and current deactivate root
- coordinator private/public key
- deactivate messages, encryption public keys
- generated deactivate ciphertexts `c1`, `c2`
- current and new active-state leaves
- state leaves and paths
- active-state paths
- deactivate tree paths
- deactivate batch start index
- current/new deactivate commitments
- `newDeactivateRoot`, `currentStateRoot`, `expectedPollId`

### AddNewKey private witness

- old private key
- deactivate index and deactivate leaf
- deactivate leaf Merkle path
- original ciphertext `c1`, `c2`
- rerandomization scalar `randomVal`
- rerandomized ciphertext `d1`, `d2`
- new public key
- poll ID and nullifier
- coordinator public key and deactivate root

## Shared subtemplates and Rust equivalents

| Template | File | Rust migration target |
| --- | --- | --- |
| `MessageToCommand` | `utils/messageToCommand.circom` | ECDH, Poseidon decrypt, packed command parsing, signature preimage extraction. |
| `MessageHasher` | `utils/messageHasher.circom` | Message hash-chain step: `Hasher13(msg[10], encPubKey[2], prevHash)`. |
| `StateLeafTransformer` | `amaci/power/stateLeafTransformer.circom` | Valid command application: active/deactivate checks, signature check, vote balance update, key/nonce update. |
| `MessageValidator` | `amaci/power/messageValidator.circom` | State index, vote option, nonce, poll ID, signature, vote-weight range, and balance checks. |
| `VerifySignature` | `utils/verifySignature.circom` | BabyJubJub EdDSA Poseidon verification over `poseidon([packed, newPubKeyX, newPubKeyY])`. |
| `Ecdh` / `PrivToPubKey` | `utils/ecdh.circom`, `utils/privToPubKey.circom` | BabyJubJub scalar multiplication with existing key preprocessing rules. |
| `ElGamalDecrypt` / `ElGamalReRandomize` | `amaci/power/lib/rerandomize.circom` | BabyJubJub ElGamal decrypt and rerandomization. |
| `QuinTreeInclusionProof`, `QuinLeafExists`, `QuinCheckRoot`, `ZeroRoot` | `utils/trees/*.circom` | 5-ary Poseidon Merkle root/path calculation and validation. |
| `UnpackElement` | `utils/unpackElement.circom` | Strict field-to-32-bit chunk decomposition, high-to-low output order. |
| `Sha256Hasher` | `utils/hasherSha256.circom` | ABI-like field hashing compatible with Circom bit order. |
| `Hasher3/4/5/10/12/13`, `HashLeftRight` | `utils/hasherPoseidon.circom` | Poseidon hash wrappers with the same treeing strategy. |

## Circuit business logic

### ProcessMessages

1. Recompute `currentStateCommitment = poseidon(currentStateRoot, currentStateSalt)`.
2. Recompute `deactivateCommitment = poseidon(activeStateRoot, deactivateRoot)`.
3. Recompute and check `inputHash`.
4. Validate `maxVoteOptions <= 5^voteOptionTreeDepth` and `numSignUps <= 5^stateTreeDepth`.
5. Recompute message hash chain from `batchStartHash` to `batchEndHash`; empty message check currently uses `encPubKeys[i][0] == 0`.
6. Prove coordinator key ownership by deriving `coordPubKey` from `coordPrivKey`.
7. Decrypt every message via ECDH + Poseidon decrypt.
8. Process messages in reverse order.
9. For each message:
   - validate command fields and signature;
   - validate active/deactivate state;
   - validate current state leaf path;
   - validate active-state leaf path;
   - validate current vote weight path;
   - update vote-option root and state leaf only if valid;
   - otherwise use sentinel index `5^stateTreeDepth - 1` or vote option `0`.
10. Recompute `newStateCommitment = poseidon(newStateRoot, newStateSalt)`.

### TallyVotes

1. Recompute `stateCommitment = poseidon(stateRoot, stateSalt)`.
2. Recompute and check `inputHash`.
3. Unpack `batchNum` and `numSignUps`.
4. Check `batchStartIndex = batchNum * 5^intStateTreeDepth <= numSignUps`.
5. Hash each 10-field state leaf and compute the state subtree root.
6. Verify the state subtree root exists in `stateRoot`.
7. For each state leaf, verify the supplied vote array root equals the leaf vote-option root, or the vote tree zero root if the state leaf VO root is zero.
8. Compute new results:
   - if first batch, ignore `currentResults`;
   - otherwise include `currentResults`;
   - add `vote * (vote + 10^24)` for each state/vote option.
9. Verify current tally commitment is zero in first batch, otherwise `poseidon(currentResultsRoot, currentResultsRootSalt)`.
10. Verify `newTallyCommitment = poseidon(newResultsRoot, newResultsRootSalt)`.

### ProcessDeactivateMessages

1. Recompute and check `inputHash`.
2. Recompute message hash chain from `batchStartHash` to `batchEndHash`; empty message check uses `msgs[i][0] == 0`.
3. Prove coordinator key ownership.
4. Decrypt each message to command.
5. Recompute `currentDeactivateCommitment = poseidon(currentActiveStateRoot, currentDeactivateRoot)`.
6. Process deactivate messages in forward order.
7. For each message:
   - verify signature over packed command;
   - decrypt current state ciphertext and require current status active;
   - require `cmdPollId == expectedPollId`;
   - verify state leaf path;
   - decrypt newly supplied `c1/c2` and bind it to the validity result;
   - derive deactivate leaf from `c1/c2` plus ECDH shared key with voter pubkey;
   - require `newActiveState != 0`;
   - update active-state root when valid;
   - insert deactivate leaf at `deactivateIndex0 + i`, or zero for empty messages.
8. Check final `newDeactivateRoot`.
9. Recompute `newDeactivateCommitment = poseidon(finalActiveStateRoot, finalDeactivateRoot)`.

### AddNewKey

1. Check `nullifier = poseidon(oldPrivateKey, pollId)`.
2. Derive ECDH shared key between old private key and coordinator public key.
3. Check `deactivateLeaf = poseidon(c1[0], c1[1], c2[0], c2[1], poseidon(sharedKey))`.
4. Verify deactivate leaf exists at `deactivateIndex` under `deactivateRoot`.
5. Rerandomize ElGamal ciphertext:
   - `d1 = base8 * randomVal + c1`
   - `d2 = coordPubKey * randomVal + c2`
6. Recompute and check `inputHash`, including `newPubKey` and `pollId`.

## Circom-specific semantics to preserve

- Field arithmetic is BN254 scalar field arithmetic, not native integer arithmetic.
- `===` must become explicit validation returning `ProofError`.
- `<==` combines assignment and constraint; Rust must compute and validate the relation.
- `<--` appears in `QuinGeneratePathIndices` for division/modulo witness assignment. It is constrained later by `n[i-1] === n[i] * 5 + out[i-1]`, `out[i] < 5`, and sum reconstruction. Rust must perform both base-5 decomposition and validation.
- `Num2Bits`, `Num2Bits_strict`, `Bits2Num`, `LessThan`, `LessEqThan`, `GreaterEqThan`, `IsZero`, `IsEqual`, and `Mux1` are constraints. Rust must not treat values as trusted booleans unless it validates `0/1`.
- `Mux1` selector semantics are `s=0 => c[0]`, `s=1 => c[1]`.
- Empty message detection differs:
  - `ProcessMessages`: `encPubKeys[i][0] == 0`.
  - `ProcessDeactivateMessages`: `msgs[i][0] == 0`.
- `UnpackElement(n)` returns high-to-low 32-bit chunks while SDK packing writes low-to-high shifts.
- Poseidon wrappers are not generic variable-length hashes; `Hasher10` and `Hasher13` are explicit two-level hashes.
- `Sha256Hasher` bit order and field conversion must be copied exactly.
- BabyJubJub private keys are expected to be preprocessed off-circuit. `PrivToPubKey` additionally checks `< SUBGROUP_ORDER`; `Ecdh` only bit-decomposes 253 bits.

## Logic that can be translated directly

- `packedVals` parsing and validation.
- `packElement` / `unpackElement`.
- Message hash chain updates.
- 5-ary Merkle path index generation and root recomputation.
- State leaf hashing layout.
- Tally result accumulation.
- Commitment hashing.
- Vote balance update formula for linear/quadratic cost.
- Public output construction and field ordering.

## Logic requiring special care

- Poseidon constants and field modulus must match Circom/circomlib exactly.
- SHA256 input encoding must match Circom bit ordering.
- BabyJubJub point addition/scalar multiplication must match circomlib formulas and subgroup assumptions.
- EdDSA verification uses a patched verifier and `BASE8`, not arbitrary Ed25519.
- Poseidon encryption/decryption uses `PoseidonDecryptWithoutCheck(7)`: it does not enforce padding/last-block checks.
- `Uint32to96` in Circom uses the decimal constant `18446744073709552000`, while `2^64 = 18446744073709551616`. This discrepancy must be tested before porting; do not silently "fix" it in Rust.
- ProcessDeactivate validity couples signature, current active status, poll ID, and new encrypted status through arithmetic equalities. Rust must reproduce the exact boolean logic.
- Some legacy JS scripts are stale relative to current circuits.

## Rust implementation status

Implemented under `zkvm-amaci/crates/proof-core`:

- typed `ProverInput` and `PublicOutput` variants for all four top-level AMACI circuits;
- `execute_proof_logic` dispatch shared by normal tests, RISC Zero, and SP1;
- BN254 field arithmetic helpers and explicit range/boolean checks;
- Circom-compatible packed value parsing, including the `Uint32to96` decimal multiplier used by the latest circuit;
- SHA256 public input hashing through the existing MACI crypto path;
- Poseidon `Hasher3/5/10/12/13` composition through existing MACI crypto functions;
- 5-ary Merkle zero roots, inclusion roots, and subtree roots;
- `ProcessMessages` latest circuit flow: input hash, coordinator key, message chain, ECDH, `PoseidonDecryptWithoutCheck(7)`, `MessageToCommand`, `MessageValidator`, `StateLeafTransformer`, vote-option root update, state-root update, and final `newStateCommitment`;
- `TallyVotes` latest circuit flow: state commitment, packed values, subtree inclusion, vote-option roots, first/non-first tally commitment rules, result update formula, and final `newTallyCommitment`;
- `ProcessDeactivateMessages` latest circuit flow: input hash, coordinator key, message chain, command decrypt/validation, active-state and deactivate-tree updates, parity binding for `c1/c2`, deactivate leaf derivation, and final commitment;
- `AddNewKey` latest circuit flow: nullifier, deactivate leaf ECDH binding, deactivate leaf inclusion, rerandomization, `newPubKey`, `pollId`, and final input hash;
- Circomlib-compatible `ElGamalDecrypt` scalar multiplication for the zero-x special case in `EscalarMulAny(253)`, which is required by existing operator fixtures.

Implemented under `zkvm-amaci/crates/proof-risc0-guest` and `zkvm-amaci/crates/proof-sp1-program`:

- feature-gated read/execute/commit wrappers;
- no AMACI business logic in either wrapper;
- no RISC0/SP1 SDK dependency in `proof-core`.

## Verified alignment

Rust tests currently cover:

- packing and unpacking semantics;
- BN254 field helper wrapping and range checks;
- the Circom `Uint32to96` constant;
- `MessageHasher` chain behavior for empty process messages;
- fixed-width Merkle/hash helper shape validation;
- ECDH zero-x identity behavior and Poseidon decrypt length/nonce guards;
- a minimal first tally batch;
- existing operator-generated latest `ProcessMessages` fixture:
  `amaci-operator/test-data/data/dora10sfhzqa0dfwxc36y94k7wce20rjkvavr5w4e2pdxvnwruv6ahj9qkrjfkt/inputs/msg/000000.json`;
- existing operator-generated latest `TallyVotes` fixture:
  `amaci-operator/test-data/data/dora10sfhzqa0dfwxc36y94k7wce20rjkvavr5w4e2pdxvnwruv6ahj9qkrjfkt/inputs/tally/000000.json`.
- generated latest `ProcessDeactivateMessages` fixture:
  `zkvm-amaci/tests/golden/process_deactivate_2_5_valid.json`;
- generated latest `AddNewKey` fixture:
  `zkvm-amaci/tests/golden/add_new_key_2_valid.json`.
- negative mutations for all four top-level circuits, including public input hash mismatches, commitment mismatches, Merkle path/root failures, message-chain failures, length/range/boolean guards, AddNewKey nullifier failure, and rerandomized ciphertext failure.

All four fixtures match the expected semantic public output fields and final commitment values in Rust. The generated Deactivate/AddNewKey fixtures were also checked against Circom with manual `--O0` compilation plus `snarkjs wtns check`.

## Remaining verification gaps

1. RISC Zero and SP1 wrappers use the documented guest APIs, but SDK versions are intentionally not pinned in this pass because this repository currently uses Cargo 1.79 and the latest SDK crates may impose newer toolchain constraints. Pinning and compiling those feature paths should be a separate adapter task.
2. Legacy `packages/circuits/scripts/amaci.js`, `client.js`, and `proofAddKey.js` remain stale relative to latest Circom and should not be used as golden sources.
3. `ProcessMessages` and `ProcessDeactivateMessages` short-circuit invalid/empty messages before expensive curve operations when those operations cannot affect the final Circom validity bit. This avoids Rust curve-library panics for witness values that Circom treats algebraically, while preserving final root/commitment behavior against golden fixtures.
4. Local Circomkit wasm tester compilation for `ProcessDeactivateMessages` fails under Circom 2.1.9 `--O1` with a constraint simplification overflow. Manual `--O0` compilation and `snarkjs wtns check` succeed for the generated fixture.
