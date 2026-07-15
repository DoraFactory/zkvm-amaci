#![no_main]

use amaci_proof_core::auth::{
    auth_keypair_from_seed_for_testing, auth_public_key_hash, sign_command_for_testing,
    verify_command_auth_signature,
};
use amaci_proof_core::crypto::{decrypt_authenticated_array, native_encrypt_for_testing};
use amaci_proof_core::field::Field;
use amaci_proof_core::hash_backend::hash_fields;
use amaci_proof_core::pq_kem::{
    decapsulate_to_fields, encapsulate_to_public_key_for_testing, encapsulate_to_seed_for_testing,
    kem_ciphertext_compact, kem_public_key_compact,
};

sp1_zkvm::entrypoint!(main);

const OP_KEM_DECAP: u8 = 1;
const OP_KEM_ENCAP: u8 = 2;
const OP_MLDSA_VERIFY: u8 = 3;
const OP_KEM_COMPACT: u8 = 4;
const OP_COMMAND_DECRYPT: u8 = 5;

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    let (op, iters) = decode_input(&input);
    let out = match op {
        OP_KEM_DECAP => profile_kem_decap(iters),
        OP_KEM_ENCAP => profile_kem_encap(iters),
        OP_MLDSA_VERIFY => profile_mldsa_verify(iters),
        OP_KEM_COMPACT => profile_kem_compact(iters),
        OP_COMMAND_DECRYPT => profile_command_decrypt(iters),
        _ => panic!("unknown crypto profile op"),
    };
    sp1_zkvm::io::commit_slice(&out);
}

fn decode_input(input: &[u8]) -> (u8, u32) {
    assert_eq!(input.len(), 5, "crypto profile input must be 5 bytes");
    let iters = u32::from_be_bytes(input[1..5].try_into().unwrap());
    assert!(iters > 0, "iters must be positive");
    (input[0], iters)
}

fn profile_kem_decap(iters: u32) -> [u8; 32] {
    let recipient_seed = Field::from(1001u32);
    let randomness = Field::from(2002u32);
    let (ciphertext, _, _) = encapsulate_to_seed_for_testing(&recipient_seed, &randomness).unwrap();
    let mut acc = Field::from(0u32);
    for _ in 0..iters {
        let shared = decapsulate_to_fields(&recipient_seed, &ciphertext).unwrap();
        acc += &shared[0];
        acc += &shared[1];
    }
    field_digest(&acc)
}

fn profile_kem_encap(iters: u32) -> [u8; 32] {
    let recipient_seed = Field::from(1001u32);
    let public_key =
        amaci_proof_core::pq_kem::kem_public_key_from_seed_for_testing(&recipient_seed);
    let mut acc = Field::from(0u32);
    for i in 0..iters {
        let randomness = Field::from(3000u32 + i);
        let (ciphertext, compact, shared) =
            encapsulate_to_public_key_for_testing(&public_key, &randomness).unwrap();
        acc += hash_fields(&compact);
        acc += hash_fields(&shared);
        acc += hash_fields(&kem_ciphertext_compact(&ciphertext));
    }
    field_digest(&acc)
}

fn profile_mldsa_verify(iters: u32) -> [u8; 32] {
    let user_seed = Field::from(4004u32);
    let command = [Field::from(1u32), Field::from(2u32), Field::from(3u32)];
    let (public_key, _) = auth_keypair_from_seed_for_testing(&user_seed);
    let public_key_hash = auth_public_key_hash(&public_key);
    let signature = sign_command_for_testing(&user_seed, &command);
    let mut ok_count = Field::from(0u32);
    for _ in 0..iters {
        if verify_command_auth_signature(&public_key_hash, &public_key, &signature, &command)
            .unwrap()
        {
            ok_count += Field::from(1u32);
        }
    }
    field_digest(&ok_count)
}

fn profile_kem_compact(iters: u32) -> [u8; 32] {
    let recipient_seed = Field::from(1001u32);
    let randomness = Field::from(2002u32);
    let public_key =
        amaci_proof_core::pq_kem::kem_public_key_from_seed_for_testing(&recipient_seed);
    let (ciphertext, _, _) =
        encapsulate_to_public_key_for_testing(&public_key, &randomness).unwrap();
    let mut acc = Field::from(0u32);
    for _ in 0..iters {
        acc += hash_fields(&kem_public_key_compact(&public_key));
        acc += hash_fields(&kem_ciphertext_compact(&ciphertext));
    }
    field_digest(&acc)
}

fn profile_command_decrypt(iters: u32) -> [u8; 32] {
    let key = [Field::from(7001u32), Field::from(7002u32)];
    let nonce = Field::from(0u32);
    let plaintext = [
        Field::from(1u32),
        Field::from(2u32),
        Field::from(3u32),
        Field::from(4u32),
        Field::from(5u32),
        Field::from(6u32),
        Field::from(7u32),
        Field::from(0u32),
        Field::from(0u32),
    ];
    let ciphertext = native_encrypt_for_testing(&plaintext, &key, &nonce, 7).unwrap();
    let mut acc = Field::from(0u32);
    for _ in 0..iters {
        let decrypted = decrypt_authenticated_array::<9>(&ciphertext, &key, &nonce, 7).unwrap();
        acc += hash_fields(&decrypted);
    }
    field_digest(&acc)
}

fn field_digest(value: &Field) -> [u8; 32] {
    amaci_proof_core::native_types::field_to_digest(value)
}
