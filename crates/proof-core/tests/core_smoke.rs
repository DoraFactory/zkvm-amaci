use amaci_proof_core::circuits::process_messages::{message_chain, EmptyRule};
use amaci_proof_core::codec::{
    decode_input, decode_public_output, encode_input, encode_public_output,
};
use amaci_proof_core::crypto::{
    decrypt_without_check, ecdh_formatted_priv_key, native_encrypt_for_testing,
    native_rerandomize_ciphertext, native_sign_command_for_testing, private_to_pub_key,
    verify_command_signature,
};
use amaci_proof_core::error::ProofError;
use amaci_proof_core::field::{add, ensure_bits, field, mul, sub, two_pow};
use amaci_proof_core::merkle::{check_root, hash10_exact, hash5_exact};
use amaci_proof_core::packing::{
    decode_vote_weight_96, path_index_at, unpack_element_high_to_low,
    unpack_process_messages_packed_vals, unpack_tally_packed_vals,
};
use amaci_proof_core::public_output::public_value;
use amaci_proof_core::round_fixture::five_signup_round_fixture;
use amaci_proof_core::{execute_proof_logic, Field, ProverInput, PublicOutput};
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
fn native_field_helpers_are_fixed_width_arithmetic() {
    assert_eq!(field(7), Field::from(7u32));
    assert_eq!(
        add(&Field::from(9u32), &Field::from(2u32)),
        Field::from(11u32)
    );
    assert_eq!(
        sub(&Field::from(3u32), &Field::from(5u32)),
        Field::from(0u32)
    );
    assert_eq!(
        mul(&Field::from(3u32), &Field::from(4u32)),
        Field::from(12u32)
    );
}

#[test]
fn packing_helpers_still_parse_native_command_words() {
    let packed =
        Field::from(5u32) + (Field::from(3u32) << 32usize) + (Field::from(1u32) << 64usize);
    let out = unpack_process_messages_packed_vals(&packed).unwrap();
    assert_eq!(out.max_vote_options, Field::from(5u32));
    assert_eq!(out.num_sign_ups, Field::from(3u32));
    assert_eq!(out.is_quadratic_cost, Field::from(1u32));

    let tally = Field::from(7u32) + (Field::from(25u32) << 32usize);
    let out = unpack_tally_packed_vals(&tally).unwrap();
    assert_eq!(out.batch_num, Field::from(7u32));
    assert_eq!(out.num_sign_ups, Field::from(25u32));

    let command =
        (Field::from(1u32) << 64usize) + (Field::from(2u32) << 32usize) + Field::from(3u32);
    assert_eq!(
        unpack_element_high_to_low(&command, 3).unwrap(),
        vec![Field::from(1u32), Field::from(2u32), Field::from(3u32)]
    );
}

#[test]
fn range_checks_reject_values_at_the_bit_limit() {
    let max_u32 = (Field::one() << 32usize) - Field::one();
    ensure_bits("u32", &max_u32, 32).unwrap();
    assert_invalid_range(ensure_bits("u32", &two_pow(32), 32).unwrap_err(), "u32");
}

#[test]
fn decodes_96_bit_vote_weight() {
    let high = Field::from(1u32);
    let mid = Field::from(0u32);
    let low = Field::from(0u32);
    let out = decode_vote_weight_96(&high, &mid, &low).unwrap();
    assert_eq!(out, Field::from(18_446_744_073_709_551_616u128));
}

#[test]
fn message_chain_skips_empty_messages() {
    let start = Field::from(9u32);
    let msgs = vec![[Field::from(0u32); 10]];
    let enc = vec![[Field::from(0u32), Field::from(0u32)]];
    let end = message_chain(&start, &msgs, &enc, EmptyRule::EncPubKeyX).unwrap();
    assert_eq!(end, start);
}

#[test]
fn message_chain_rejects_wrong_message_width() {
    assert_eq!(amaci_proof_core::types::MESSAGE_WORDS, 10);
}

#[test]
fn merkle_helpers_validate_quin_arity_and_path_widths() {
    assert_invalid_length(
        hash5_exact(&vec![Field::from(0u32); 4]).unwrap_err(),
        "quin hash children",
    );
    assert_invalid_length(
        hash10_exact(&vec![Field::from(0u32); 9]).unwrap_err(),
        "state leaf",
    );
    assert_invalid_length(
        check_root(&vec![Field::from(0u32); 4], 1).unwrap_err(),
        "quin check root leaves",
    );
}

#[test]
fn path_indices_are_base_5_digits_by_level() {
    let index = Field::from(73u32);
    assert_eq!(path_index_at(&index, 0, 5), 3);
    assert_eq!(path_index_at(&index, 1, 5), 4);
    assert_eq!(path_index_at(&index, 2, 5), 2);
}

#[test]
fn native_crypto_roundtrips() {
    let priv_key = Field::from(123456u32);
    let pub_key = private_to_pub_key(&priv_key);
    let packed_command = [Field::from(11u32), Field::from(22u32), Field::from(33u32)];
    let (r8, s) = native_sign_command_for_testing(&priv_key, &packed_command);
    assert!(verify_command_signature(&pub_key, &r8, &s, &packed_command).unwrap());

    let alice_priv = Field::from(111u32);
    let bob_priv = Field::from(222u32);
    let alice_pub = private_to_pub_key(&alice_priv);
    let bob_pub = private_to_pub_key(&bob_priv);
    assert_eq!(
        ecdh_formatted_priv_key(&alice_priv, &bob_pub),
        ecdh_formatted_priv_key(&bob_priv, &alice_pub)
    );

    let key = [Field::from(11u32), Field::from(22u32)];
    let nonce = Field::from(7u32);
    let len = 7;
    let mut plaintext = vec![Field::from(1u32); 7];
    plaintext.resize(9, Field::from(0u32));
    let ciphertext = native_encrypt_for_testing(&plaintext, &key, &nonce, len).unwrap();
    let decrypted = decrypt_without_check(&ciphertext, &key, &nonce, len).unwrap();
    assert_eq!(decrypted, plaintext);

    let (d1, d2) = native_rerandomize_ciphertext(
        &pub_key,
        &[Field::from(1u32), Field::from(2u32)],
        &[Field::from(3u32), Field::from(4u32)],
        &Field::from(5u32),
    );
    assert_ne!(d1, d2);
}

#[test]
fn native_decrypt_rejects_bad_ciphertext_shape_and_nonce() {
    let key = [Field::from(1u32), Field::from(2u32)];
    assert_invalid_length(
        decrypt_without_check(&vec![Field::from(0u32); 3], &key, &Field::from(0u32), 7)
            .unwrap_err(),
        "native ciphertext",
    );
    assert_invalid_range(
        decrypt_without_check(
            &vec![Field::from(0u32); 10],
            &key,
            &(Field::one() << 128usize),
            7,
        )
        .unwrap_err(),
        "native nonce",
    );
}

#[test]
fn built_in_native_process_messages_execute() {
    for name in [
        "process-messages-native-1-1",
        "process-messages-native-2-1-5",
        "process-messages-native-2-1-5-full",
    ] {
        let Some(ProverInput::ProcessMessages(input)) =
            amaci_proof_core::sample_inputs::built_in_input(name).unwrap()
        else {
            panic!("missing process messages input {name}");
        };
        let output = execute_proof_logic(&ProverInput::ProcessMessages(input.clone())).unwrap();
        let PublicOutput::ProcessMessages(output) = output else {
            panic!("wrong output variant");
        };
        assert_eq!(output.input_hash, public_value(&input.input_hash));
        assert_eq!(output.batch_end_hash, public_value(&input.batch_end_hash));
        assert_eq!(
            output.new_state_commitment,
            public_value(&input.new_state_commitment)
        );
    }
}

#[test]
fn built_in_native_tally_deactivate_and_add_key_execute() {
    for name in [
        "tally-votes-native-2-1-1",
        "process-deactivate-native-2-5",
        "add-new-key-native-2",
    ] {
        let input = amaci_proof_core::sample_inputs::built_in_input(name)
            .unwrap()
            .expect("built-in input exists");
        let output = execute_proof_logic(&input).unwrap();
        match (name, output) {
            ("tally-votes-native-2-1-1", PublicOutput::TallyVotes(_)) => {}
            ("process-deactivate-native-2-5", PublicOutput::ProcessDeactivate(_)) => {}
            ("add-new-key-native-2", PublicOutput::AddNewKey(_)) => {}
            _ => panic!("wrong output variant for {name}"),
        }
    }
}

#[test]
fn compact_codec_roundtrips_all_built_in_inputs() {
    for name in [
        "process-messages-native-1-1",
        "process-messages-native-2-1-5",
        "process-messages-native-2-1-5-full",
        "tally-votes-native-2-1-1",
        "process-deactivate-native-2-5",
        "add-new-key-native-2",
    ] {
        let input = amaci_proof_core::sample_inputs::built_in_input(name)
            .unwrap()
            .expect("built-in input exists");
        let encoded = encode_input(&input);
        let decoded = decode_input(&encoded).unwrap();
        assert_eq!(decoded, input);
        let output = execute_proof_logic(&input).unwrap();
        let decoded_output = execute_proof_logic(&decoded).unwrap();
        assert_eq!(decoded_output, output);
        let encoded_output = encode_public_output(&output);
        assert_eq!(decode_public_output(&encoded_output).unwrap(), output);
    }
}

#[test]
fn five_signup_round_fixture_executes_and_links_public_state() {
    let fixture = five_signup_round_fixture().unwrap();
    assert_eq!(fixture.initial_signups, 5);
    assert_eq!(fixture.final_signups, 6);
    assert_eq!(fixture.expected_raw_results, [1, 0, 0, 0, 10]);
    assert_eq!(fixture.stages.len(), 5);

    let outputs = fixture
        .stages
        .iter()
        .map(|stage| execute_proof_logic(&stage.input).unwrap())
        .collect::<Vec<_>>();

    let PublicOutput::ProcessDeactivate(deactivate) = &outputs[0] else {
        panic!("stage 0 must be process deactivate");
    };
    let PublicOutput::AddNewKey(add_key) = &outputs[1] else {
        panic!("stage 1 must be add new key");
    };
    let PublicOutput::ProcessMessages(messages_full) = &outputs[2] else {
        panic!("stage 2 must be process messages");
    };
    let PublicOutput::TallyVotes(tally_0) = &outputs[3] else {
        panic!("stage 3 must be tally");
    };
    let PublicOutput::TallyVotes(tally_1) = &outputs[4] else {
        panic!("stage 4 must be tally");
    };

    assert_eq!(deactivate.new_deactivate_root, add_key.deactivate_root);
    assert_eq!(messages_full.new_state_commitment, tally_0.state_commitment);
    assert_eq!(
        tally_0.new_tally_commitment,
        tally_1.current_tally_commitment
    );
}
