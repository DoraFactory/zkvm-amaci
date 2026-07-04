use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::hash_backend::hash_fields;
use crate::native_types::{field_to_digest, NativeCommand};
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

pub fn private_to_pub_key(formatted_priv_key: &Field) -> [Field; 2] {
    crate::pq_kem::private_to_pub_key(formatted_priv_key)
}

pub fn native_rerandomize_ciphertext(
    coord_pub_key: &[Field; 2],
    c1: &[Field; 2],
    c2: &[Field; 2],
    random_val: &Field,
) -> ([Field; 2], [Field; 2]) {
    let d1 = hash_to_pair(
        b"AMACI_ZKVM_NATIVE_RERANDOMIZE_D1_V1",
        &[
            &coord_pub_key[0],
            &coord_pub_key[1],
            &c1[0],
            &c1[1],
            random_val,
        ],
    );
    let d2 = hash_to_pair(
        b"AMACI_ZKVM_NATIVE_RERANDOMIZE_D2_V1",
        &[
            &coord_pub_key[0],
            &coord_pub_key[1],
            &c2[0],
            &c2[1],
            random_val,
        ],
    );
    (d1, d2)
}

pub fn native_command_message(packed_command: &[Field; 3]) -> ProofResult<[u8; 32]> {
    Ok(NativeCommand::from_packed_fields(packed_command)?.message_digest())
}

fn field_to_fixed_be_lossy(value: &Field) -> [u8; 32] {
    field_to_digest(value)
}

pub fn decrypt_deactivation_flag(
    c1: &[Field; 2],
    c2: &[Field; 2],
    formatted_priv_key: &Field,
) -> ProofResult<(Field, bool)> {
    if c1.iter().all(Zero::is_zero) && c2.iter().all(Zero::is_zero) {
        return Ok((Field::from(0u32), false));
    }
    let x = hash_fields(&[
        c1[0].clone(),
        c1[1].clone(),
        c2[0].clone(),
        c2[1].clone(),
        formatted_priv_key.clone(),
    ]);
    let is_odd = x.bit(0);
    Ok((x, is_odd))
}

pub fn decrypt_without_check(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<Vec<Field>> {
    decrypt_payload(ciphertext, key, nonce, len)
}

pub fn decrypt_without_check_array<const N: usize>(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<[Field; N]> {
    decrypt_payload_array(ciphertext, key, nonce, len)
}

fn decrypt_payload(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<Vec<Field>> {
    let decrypted_len = padded_decrypt_len(len);
    if ciphertext.len() != decrypted_len + 1 {
        return Err(ProofError::InvalidLength {
            name: "native ciphertext",
            expected: decrypted_len + 1,
            actual: ciphertext.len(),
        });
    }
    validate_native_nonce(nonce)?;

    let stream_prefix = native_decrypt_stream_prefix(key, nonce, len);
    let mut decrypted = Vec::with_capacity(decrypted_len);
    for i in 0..decrypted_len {
        decrypted.push(native_stream_xor(
            &ciphertext[i],
            &native_decrypt_stream_word(&stream_prefix, i),
        ));
    }
    Ok(decrypted)
}

fn decrypt_payload_array<const N: usize>(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<[Field; N]> {
    let decrypted_len = padded_decrypt_len(len);
    if decrypted_len != N {
        return Err(ProofError::InvalidLength {
            name: "native plaintext fixed length",
            expected: decrypted_len,
            actual: N,
        });
    }
    if ciphertext.len() != decrypted_len + 1 {
        return Err(ProofError::InvalidLength {
            name: "native ciphertext",
            expected: decrypted_len + 1,
            actual: ciphertext.len(),
        });
    }
    validate_native_nonce(nonce)?;

    let stream_prefix = native_decrypt_stream_prefix(key, nonce, len);
    Ok(std::array::from_fn(|i| {
        native_stream_xor(
            &ciphertext[i],
            &native_decrypt_stream_word(&stream_prefix, i),
        )
    }))
}

pub fn native_encrypt_for_testing(
    plaintext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<Vec<Field>> {
    let decrypted_len = padded_decrypt_len(len);
    if plaintext.len() != decrypted_len {
        return Err(ProofError::InvalidLength {
            name: "native plaintext",
            expected: decrypted_len,
            actual: plaintext.len(),
        });
    }
    validate_native_nonce(nonce)?;

    let stream_prefix = native_decrypt_stream_prefix(key, nonce, len);
    let mut ciphertext = Vec::with_capacity(decrypted_len + 1);
    for (i, value) in plaintext.iter().enumerate() {
        ciphertext.push(native_stream_xor(
            value,
            &native_decrypt_stream_word(&stream_prefix, i),
        ));
    }
    ciphertext.push(hash_fields(&ciphertext));
    Ok(ciphertext)
}

fn native_decrypt_stream_prefix(key: &[Field; 2], nonce: &Field, len: usize) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"AMACI_ZKVM_NATIVE_DECRYPT_STREAM_V1");
    hasher.update(field_to_fixed_be_lossy(&key[0]));
    hasher.update(field_to_fixed_be_lossy(&key[1]));
    hasher.update(field_to_fixed_be_lossy(nonce));
    hasher.update((len as u64).to_be_bytes());
    hasher
}

fn native_decrypt_stream_word(stream_prefix: &Sha256, index: usize) -> [u8; 32] {
    let mut hasher = stream_prefix.clone();
    hasher.update((index as u64).to_be_bytes());
    hasher.finalize().into()
}

fn native_stream_xor(value: &Field, stream_word: &[u8; 32]) -> Field {
    let mut value_bytes = field_to_fixed_be_lossy(value);
    for (byte, stream_byte) in value_bytes.iter_mut().zip(stream_word) {
        *byte ^= stream_byte;
    }
    Field::from_be_bytes(value_bytes)
}

fn padded_decrypt_len(len: usize) -> usize {
    let mut decrypted_len = len;
    while decrypted_len % 3 != 0 {
        decrypted_len += 1;
    }
    decrypted_len
}

fn validate_native_nonce(nonce: &Field) -> ProofResult<()> {
    if nonce >= &(Field::one() << 128usize) {
        return Err(ProofError::InvalidRange {
            name: "native nonce",
            value: nonce.clone(),
            max: (Field::one() << 128usize) - Field::one(),
        });
    }
    Ok(())
}

fn hash_to_pair(domain: &[u8], fields: &[&Field]) -> [Field; 2] {
    let mut left = Sha256::new();
    left.update(domain);
    left.update([0u8]);
    for field in fields {
        left.update(field_to_fixed_be_lossy(field));
    }

    let mut right = Sha256::new();
    right.update(domain);
    right.update([1u8]);
    for field in fields {
        right.update(field_to_fixed_be_lossy(field));
    }

    [
        Field::from_be_bytes(left.finalize().into()),
        Field::from_be_bytes(right.finalize().into()),
    ]
}
