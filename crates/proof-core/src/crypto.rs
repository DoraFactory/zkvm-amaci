use crate::error::{ProofError, ProofResult};
use crate::field::Field;
use crate::hash_backend::hash_fields;
use crate::native_types::{field_to_digest, NativeCommand};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub fn private_to_pub_key(formatted_priv_key: &Field) -> [Field; 2] {
    native_key_material(formatted_priv_key).pub_key
}

pub fn ecdh_formatted_priv_key(formatted_priv_key: &Field, pub_key: &[Field; 2]) -> [Field; 2] {
    ecdh_formatted_priv_key_native(formatted_priv_key, pub_key)
        .unwrap_or_else(|_| [Field::from(0u32), Field::one()])
}

pub fn verify_command_signature(
    pub_key: &[Field; 2],
    r8: &[Field; 2],
    s: &Field,
    packed_command: &[Field; 3],
) -> ProofResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(&field_to_fixed_be(
        pub_key_ed25519(pub_key),
        "Ed25519 public key",
    )?)
    .map_err(|e| ProofError::Crypto(format!("invalid Ed25519 public key: {e}")))?;
    let signature = Ed25519Signature::from_bytes(&join_ed25519_signature(r8, s)?);
    Ok(verifying_key
        .verify(&native_command_message(packed_command)?, &signature)
        .is_ok())
}

pub fn native_sign_command_for_testing(
    formatted_priv_key: &Field,
    packed_command: &[Field; 3],
) -> ([Field; 2], Field) {
    let key_material = native_key_material(formatted_priv_key);
    let signature = key_material.signing_key.sign(
        &native_command_message(packed_command).expect("test command fields fit native widths"),
    );
    split_ed25519_signature(signature.to_bytes())
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

struct NativeKeyMaterial {
    signing_key: SigningKey,
    x25519_secret: X25519StaticSecret,
    pub_key: [Field; 2],
}

fn native_key_material(formatted_priv_key: &Field) -> NativeKeyMaterial {
    let signing_key = SigningKey::from_bytes(&native_private_key_seed(formatted_priv_key));
    let x25519_secret = X25519StaticSecret::from(native_x25519_secret_seed(formatted_priv_key));
    let ed_pub = Field::from_be_bytes(signing_key.verifying_key().to_bytes());
    let x_pub = Field::from_be_bytes(X25519PublicKey::from(&x25519_secret).to_bytes());
    NativeKeyMaterial {
        signing_key,
        x25519_secret,
        pub_key: [ed_pub, x_pub],
    }
}

fn ecdh_formatted_priv_key_native(
    formatted_priv_key: &Field,
    pub_key: &[Field; 2],
) -> ProofResult<[Field; 2]> {
    if pub_key[1].is_zero() {
        return Ok([Field::from(0u32), Field::one()]);
    }
    let secret = native_key_material(formatted_priv_key).x25519_secret;
    let public = X25519PublicKey::from(field_to_fixed_be(
        pub_key_x25519(pub_key),
        "X25519 public key",
    )?);
    let shared = secret.diffie_hellman(&public);
    let mut hasher = Sha256::new();
    hasher.update(b"AMACI_ZKVM_NATIVE_X25519_SHARED_V1");
    hasher.update(shared.to_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    Ok([
        Field::from_be_slice(&digest[0..16]),
        Field::from_be_slice(&digest[16..32]),
    ])
}

fn native_private_key_seed(formatted_priv_key: &Field) -> [u8; 32] {
    native_seed(b"AMACI_ZKVM_NATIVE_ED25519_SEED_V1", formatted_priv_key)
}

fn native_x25519_secret_seed(formatted_priv_key: &Field) -> [u8; 32] {
    native_seed(b"AMACI_ZKVM_NATIVE_X25519_SEED_V1", formatted_priv_key)
}

fn native_seed(domain: &[u8], formatted_priv_key: &Field) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(field_to_fixed_be_lossy(formatted_priv_key));
    hasher.finalize().into()
}

fn native_command_message(packed_command: &[Field; 3]) -> ProofResult<[u8; 32]> {
    Ok(NativeCommand::from_packed_fields(packed_command)?.message_digest())
}

fn split_ed25519_signature(bytes: [u8; 64]) -> ([Field; 2], Field) {
    (
        [
            Field::from_be_slice(&bytes[0..22]),
            Field::from_be_slice(&bytes[22..43]),
        ],
        Field::from_be_slice(&bytes[43..64]),
    )
}

fn join_ed25519_signature(r8: &[Field; 2], s: &Field) -> ProofResult<[u8; 64]> {
    let mut bytes = [0u8; 64];
    write_fixed_be(&mut bytes[0..22], &r8[0], "Ed25519 signature chunk 0")?;
    write_fixed_be(&mut bytes[22..43], &r8[1], "Ed25519 signature chunk 1")?;
    write_fixed_be(&mut bytes[43..64], s, "Ed25519 signature chunk 2")?;
    Ok(bytes)
}

fn pub_key_ed25519(pub_key: &[Field; 2]) -> &Field {
    &pub_key[0]
}

fn pub_key_x25519(pub_key: &[Field; 2]) -> &Field {
    &pub_key[1]
}

fn field_to_fixed_be(value: &Field, name: &'static str) -> ProofResult<[u8; 32]> {
    let mut out = [0u8; 32];
    write_fixed_be(&mut out, value, name)?;
    Ok(out)
}

fn write_fixed_be(out: &mut [u8], value: &Field, name: &'static str) -> ProofResult<()> {
    let bytes: [u8; 32] = value.to_be_bytes();
    if bytes[0..bytes.len().saturating_sub(out.len())]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ProofError::InvalidLength {
            name,
            expected: out.len(),
            actual: bytes.len(),
        });
    }
    let offset = bytes.len() - out.len();
    out.copy_from_slice(&bytes[offset..]);
    Ok(())
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
