use amaci_proof_core::circuits::process_messages::{message_chain, EmptyRule};
use amaci_proof_core::crypto::{ecdh_formatted_priv_key, poseidon_decrypt_without_check};
#[cfg(feature = "zkvm-native-crypto")]
use amaci_proof_core::crypto::{
    native_encrypt_for_testing, native_sign_command_for_testing, private_to_pub_key,
    verify_command_signature,
};
use amaci_proof_core::error::ProofError;
use amaci_proof_core::field::{add, ensure_bits, field, mul, sub, two_pow};
use amaci_proof_core::hash_backend::{hash_fields, hash_pair, hash_public_inputs, hash_state_leaf};
use amaci_proof_core::merkle::{check_root, hash10_exact, hash5_exact, root_from_path};
use amaci_proof_core::packing::{
    path_index_at, uint32_to_96_circom, unpack_element_high_to_low,
    unpack_process_messages_packed_vals, unpack_tally_packed_vals,
};
use amaci_proof_core::{execute_proof_logic, ProverInput, TallyVotesInput};
use maci_crypto::SNARK_FIELD_SIZE;
use num_bigint::BigUint;
use num_traits::One;

fn assert_invalid_length(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::InvalidLength { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected invalid length for {expected_name}, got {other:?}"),
    }
}

fn assert_invalid_range(error: ProofError, expected_name: &'static str) {
    match error {
        ProofError::InvalidRange { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected invalid range for {expected_name}, got {other:?}"),
    }
}

#[test]
fn unpacks_latest_process_messages_packed_vals() {
    let packed =
        BigUint::from(5u32) + (BigUint::from(3u32) << 32usize) + (BigUint::from(1u32) << 64usize);
    let out = unpack_process_messages_packed_vals(&packed).unwrap();
    assert_eq!(out.max_vote_options, BigUint::from(5u32));
    assert_eq!(out.num_sign_ups, BigUint::from(3u32));
    assert_eq!(out.is_quadratic_cost, BigUint::from(1u32));
}

#[test]
fn field_helpers_reduce_mod_snark_field() {
    let modulus = SNARK_FIELD_SIZE.clone();
    assert_eq!(field(&modulus + BigUint::from(7u32)), BigUint::from(7u32));
    assert_eq!(
        add(&(modulus.clone() - 1u32), &BigUint::from(2u32)),
        BigUint::one()
    );
    assert_eq!(
        sub(&BigUint::from(3u32), &BigUint::from(5u32)),
        modulus - 2u32
    );
    assert_eq!(
        mul(&BigUint::from(3u32), &BigUint::from(4u32)),
        BigUint::from(12u32)
    );
}

#[test]
fn range_checks_reject_values_at_the_bit_limit() {
    let max_u32 = (BigUint::one() << 32usize) - BigUint::one();
    ensure_bits("u32", &max_u32, 32).unwrap();
    assert_invalid_range(ensure_bits("u32", &two_pow(32), 32).unwrap_err(), "u32");
}

#[test]
fn unpack_element_outputs_high_to_low_chunks() {
    let packed =
        (BigUint::from(1u32) << 64usize) + (BigUint::from(2u32) << 32usize) + BigUint::from(3u32);
    let chunks = unpack_element_high_to_low(&packed, 3).unwrap();
    assert_eq!(
        chunks,
        vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32)
        ]
    );
}

#[test]
fn unpacks_tally_packed_vals() {
    let packed = BigUint::from(7u32) + (BigUint::from(25u32) << 32usize);
    let out = unpack_tally_packed_vals(&packed).unwrap();
    assert_eq!(out.batch_num, BigUint::from(7u32));
    assert_eq!(out.num_sign_ups, BigUint::from(25u32));
}

#[test]
fn preserves_circom_uint32_to_96_constant() {
    let high = BigUint::from(1u32);
    let mid = BigUint::from(0u32);
    let low = BigUint::from(0u32);
    let out = uint32_to_96_circom(&high, &mid, &low).unwrap();
    assert_eq!(out, BigUint::from(18_446_744_073_709_552_000u128));
}

#[test]
fn process_message_chain_keeps_empty_messages() {
    let start = BigUint::from(9u32);
    let msgs = vec![vec![BigUint::from(0u32); 10]];
    let enc = vec![[BigUint::from(0u32), BigUint::from(0u32)]];
    let end = message_chain(&start, &msgs, &enc, EmptyRule::EncPubKeyX).unwrap();
    assert_eq!(end, start);
}

#[test]
fn message_chain_rejects_wrong_message_width() {
    let start = BigUint::from(9u32);
    let msgs = vec![vec![BigUint::from(0u32); 9]];
    let enc = vec![[BigUint::from(1u32), BigUint::from(2u32)]];
    assert_invalid_length(
        message_chain(&start, &msgs, &enc, EmptyRule::EncPubKeyX).unwrap_err(),
        "message",
    );
}

#[test]
fn merkle_helpers_validate_quin_arity_and_path_widths() {
    assert_invalid_length(
        hash5_exact(&vec![BigUint::from(0u32); 4]).unwrap_err(),
        "quin hash children",
    );
    assert_invalid_length(
        hash10_exact(&vec![BigUint::from(0u32); 9]).unwrap_err(),
        "state leaf",
    );
    assert_invalid_length(
        check_root(&vec![BigUint::from(0u32); 4], 1).unwrap_err(),
        "quin check root leaves",
    );
    assert_invalid_length(
        root_from_path(
            &BigUint::from(0u32),
            &BigUint::from(0u32),
            &[vec![BigUint::from(0u32); 3]],
        )
        .unwrap_err(),
        "quin path siblings",
    );
}

#[test]
fn path_indices_are_base_5_digits_by_level() {
    let index = BigUint::from(73u32);
    assert_eq!(path_index_at(&index, 0, 5), 3);
    assert_eq!(path_index_at(&index, 1, 5), 4);
    assert_eq!(path_index_at(&index, 2, 5), 2);
}

#[test]
fn ecdh_zero_x_pub_key_matches_circom_identity_behavior() {
    let out = ecdh_formatted_priv_key(
        &BigUint::from(123u32),
        &[BigUint::from(0u32), BigUint::from(0u32)],
    );
    assert_eq!(out, [BigUint::from(0u32), BigUint::one()]);
}

#[cfg(feature = "zkvm-native-crypto")]
#[test]
fn native_ed25519_command_signature_roundtrips() {
    let priv_key = BigUint::from(123456u32);
    let pub_key = private_to_pub_key(&priv_key);
    let packed_command = [
        BigUint::from(11u32),
        BigUint::from(22u32),
        BigUint::from(33u32),
    ];
    let (r8, s) = native_sign_command_for_testing(&priv_key, &packed_command);
    assert!(verify_command_signature(&pub_key, &r8, &s, &packed_command).unwrap());

    let bad_command = [
        BigUint::from(11u32),
        BigUint::from(22u32),
        BigUint::from(34u32),
    ];
    assert!(!verify_command_signature(&pub_key, &r8, &s, &bad_command).unwrap());
}

#[cfg(feature = "zkvm-native-crypto")]
#[test]
fn native_x25519_shared_key_roundtrips() {
    let alice_priv = BigUint::from(111u32);
    let bob_priv = BigUint::from(222u32);
    let alice_pub = private_to_pub_key(&alice_priv);
    let bob_pub = private_to_pub_key(&bob_priv);

    let alice_shared = ecdh_formatted_priv_key(&alice_priv, &bob_pub);
    let bob_shared = ecdh_formatted_priv_key(&bob_priv, &alice_pub);
    assert_eq!(alice_shared, bob_shared);
    assert_ne!(alice_shared, [BigUint::from(0u32), BigUint::one()]);
}

#[cfg(feature = "zkvm-native-crypto")]
#[test]
fn native_decrypt_roundtrips() {
    let key = [BigUint::from(11u32), BigUint::from(22u32)];
    let nonce = BigUint::from(7u32);
    let len = 7;
    let mut plaintext = vec![
        BigUint::from(1u32),
        BigUint::from(2u32),
        BigUint::from(3u32),
        BigUint::from(4u32),
        BigUint::from(5u32),
        BigUint::from(6u32),
        BigUint::from(7u32),
    ];
    plaintext.resize(9, BigUint::from(0u32));

    let ciphertext = native_encrypt_for_testing(&plaintext, &key, &nonce, len).unwrap();
    let decrypted = poseidon_decrypt_without_check(&ciphertext, &key, &nonce, len).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[cfg(feature = "zkvm-native-crypto")]
#[test]
fn executes_native_single_valid_process_message() {
    let input = amaci_proof_core::sample_inputs::process_messages_native_1_1().unwrap();
    let output = execute_proof_logic(&ProverInput::ProcessMessages(input.clone())).unwrap();
    let amaci_proof_core::PublicOutput::ProcessMessages(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, input.input_hash);
    assert_eq!(output.new_state_commitment, input.new_state_commitment);
}

#[cfg(feature = "zkvm-native-crypto")]
#[test]
fn executes_native_process_messages_2_1_5() {
    let input = amaci_proof_core::sample_inputs::process_messages_native_2_1_5().unwrap();
    let output = execute_proof_logic(&ProverInput::ProcessMessages(input.clone())).unwrap();
    let amaci_proof_core::PublicOutput::ProcessMessages(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, input.input_hash);
    assert_eq!(output.batch_end_hash, input.batch_end_hash);
    assert_eq!(output.new_state_commitment, input.new_state_commitment);
}

#[test]
fn poseidon_decrypt_rejects_bad_ciphertext_shape_and_nonce() {
    let key = [BigUint::from(1u32), BigUint::from(2u32)];
    assert_invalid_length(
        poseidon_decrypt_without_check(
            &vec![BigUint::from(0u32); 3],
            &key,
            &BigUint::from(0u32),
            7,
        )
        .unwrap_err(),
        "poseidon ciphertext",
    );
    assert_invalid_range(
        poseidon_decrypt_without_check(
            &vec![BigUint::from(0u32); 10],
            &key,
            &(BigUint::one() << 128usize),
            7,
        )
        .unwrap_err(),
        "poseidon nonce",
    );
}

#[test]
fn executes_minimal_first_tally_batch() {
    let packed_vals = BigUint::from(0u32) + (BigUint::from(1u32) << 32usize);
    let zeros5 = vec![BigUint::from(0u32); 5];
    let zero_state_leaf = vec![BigUint::from(0u32); 10];
    let state_leaf_hash = hash_state_leaf(&zero_state_leaf).unwrap();
    let state_root = hash_fields(&[
        state_leaf_hash,
        BigUint::from(0u32),
        BigUint::from(0u32),
        BigUint::from(0u32),
        BigUint::from(0u32),
    ]);
    let state_salt = BigUint::from(11u32);
    let state_commitment = hash_pair(&state_root, &state_salt);
    let current_tally_commitment = BigUint::from(0u32);
    let votes = vec![vec![BigUint::from(0u32); 5]];
    let current_results = vec![BigUint::from(0u32); 5];
    let new_results_root_salt = BigUint::from(12u32);
    let new_results_root = hash_fields(&zeros5);
    let new_tally_commitment = hash_pair(&new_results_root, &new_results_root_salt);
    let input_hash = hash_public_inputs(&[
        packed_vals.clone(),
        state_commitment.clone(),
        current_tally_commitment.clone(),
        new_tally_commitment.clone(),
    ]);

    let input = TallyVotesInput {
        state_tree_depth: 1,
        int_state_tree_depth: 0,
        vote_option_tree_depth: 1,
        input_hash: input_hash.clone(),
        packed_vals,
        state_root: state_root.clone(),
        state_salt,
        state_commitment,
        current_tally_commitment,
        new_tally_commitment,
        state_leaf: vec![zero_state_leaf],
        state_path_elements: vec![vec![
            BigUint::from(0u32),
            BigUint::from(0u32),
            BigUint::from(0u32),
            BigUint::from(0u32),
        ]],
        votes,
        current_results,
        current_results_root_salt: BigUint::from(0u32),
        new_results_root_salt,
    };

    let output = execute_proof_logic(&ProverInput::TallyVotes(input)).unwrap();
    let amaci_proof_core::PublicOutput::TallyVotes(output) = output else {
        panic!("wrong output variant");
    };
    assert_eq!(output.input_hash, input_hash);
}
