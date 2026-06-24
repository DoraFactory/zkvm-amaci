use crate::error::{ProofError, ProofResult};
#[cfg(not(feature = "zkvm-native-crypto"))]
use crate::field::sub;
use crate::field::Field;
use crate::hash_backend::hash_fields;
#[cfg(not(feature = "zkvm-native-crypto"))]
use ark_bn254::Fr;
#[cfg(not(feature = "zkvm-native-crypto"))]
use ark_ff::{BigInteger, Field as ArkField, PrimeField};
#[cfg(not(feature = "zkvm-native-crypto"))]
use baby_jubjub::base8;
#[cfg(not(feature = "zkvm-native-crypto"))]
use baby_jubjub::{mul_point_escalar, EdFr, EdwardsAffine, Fq};
#[cfg(feature = "zkvm-native-crypto")]
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(not(feature = "zkvm-native-crypto"))]
use eddsa_poseidon::Signature as PoseidonSignature;
#[cfg(not(feature = "zkvm-native-crypto"))]
use light_poseidon::parameters::bn254_x5;
#[cfg(not(feature = "zkvm-native-crypto"))]
use light_poseidon::PoseidonParameters;
#[cfg(not(feature = "zkvm-native-crypto"))]
use maci_crypto::keys::verify_signature_eddsa;
#[cfg(not(feature = "zkvm-native-crypto"))]
use maci_crypto::SNARK_FIELD_SIZE;
use num_bigint::BigUint;
use num_traits::{One, Zero};
#[cfg(feature = "zkvm-native-crypto")]
use sha2::{Digest, Sha256};
#[cfg(not(feature = "zkvm-native-crypto"))]
use std::sync::OnceLock;
#[cfg(feature = "zkvm-native-crypto")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[cfg(not(feature = "zkvm-native-crypto"))]
static BASE8_CIRCOM: OnceLock<[Field; 2]> = OnceLock::new();
#[cfg(not(feature = "zkvm-native-crypto"))]
static ELGAMAL_PRIVKEY_MAX: OnceLock<Field> = OnceLock::new();
#[cfg(not(feature = "zkvm-native-crypto"))]
static FIELD_MINUS_TWO: OnceLock<Field> = OnceLock::new();

#[cfg(not(feature = "zkvm-native-crypto"))]
fn base8_circom() -> &'static [Field; 2] {
    BASE8_CIRCOM.get_or_init(|| {
        [
            BigUint::parse_bytes(
                b"5299619240641551281634865583518297030282874472190772894086521144482721001553",
                10,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"16950150798460657717958625567821834550301663161624707787222815936182638968203",
                10,
            )
            .unwrap(),
        ]
    })
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn elgamal_privkey_max() -> &'static Field {
    ELGAMAL_PRIVKEY_MAX.get_or_init(|| (BigUint::one() << 253usize) - BigUint::one())
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn field_minus_two() -> &'static Field {
    FIELD_MINUS_TWO.get_or_init(|| &*SNARK_FIELD_SIZE - BigUint::from(2u32))
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn field_to_fr(value: &Field) -> Fr {
    Fr::from_le_bytes_mod_order(&(value % &*SNARK_FIELD_SIZE).to_bytes_le())
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn fr_to_field(value: Fr) -> Field {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le())
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn field_to_edfr(value: &Field) -> EdFr {
    EdFr::from_le_bytes_mod_order(&value.to_bytes_le())
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn pubkey_to_point(pub_key: &[Field; 2]) -> EdwardsAffine {
    let x = Fq::from_le_bytes_mod_order(&pub_key[0].to_bytes_le());
    let y = Fq::from_le_bytes_mod_order(&pub_key[1].to_bytes_le());
    EdwardsAffine::new_unchecked(x, y)
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn point_to_pubkey(point: EdwardsAffine) -> [Field; 2] {
    [
        BigUint::from_bytes_le(&point.x.into_bigint().to_bytes_le()),
        BigUint::from_bytes_le(&point.y.into_bigint().to_bytes_le()),
    ]
}

/// Mirrors `utils/privToPubKey.circom::PrivToPubKey`.
pub fn private_to_pub_key(formatted_priv_key: &Field) -> [Field; 2] {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        native_private_to_pub_key(formatted_priv_key)
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        let scalar = field_to_edfr(formatted_priv_key);
        point_to_pubkey(mul_point_escalar(&base8(), scalar))
    }
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_private_to_pub_key(formatted_priv_key: &Field) -> [Field; 2] {
    native_key_material(formatted_priv_key).pub_key
}

/// Mirrors `utils/ecdh.circom::Ecdh`.
pub fn ecdh_formatted_priv_key(formatted_priv_key: &Field, pub_key: &[Field; 2]) -> [Field; 2] {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        return ecdh_formatted_priv_key_native(formatted_priv_key, pub_key)
            .unwrap_or_else(|_| [BigUint::from(0u32), BigUint::one()]);
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        if pub_key[0].is_zero() {
            return [BigUint::from(0u32), BigUint::one()];
        }
        let scalar = field_to_edfr(formatted_priv_key);
        point_to_pubkey(mul_point_escalar(&pubkey_to_point(pub_key), scalar))
    }
}

/// Mirrors `utils/verifySignature.circom::VerifySignature`.
pub fn verify_command_signature(
    pub_key: &[Field; 2],
    r8: &[Field; 2],
    s: &Field,
    packed_command: &[Field; 3],
) -> ProofResult<bool> {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        verify_command_signature_native(pub_key, r8, s, packed_command)
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        let msg_hash = hash_fields(packed_command);
        let signature = PoseidonSignature {
            r8: pubkey_to_point(r8),
            s: s.clone(),
        };
        verify_signature_eddsa(&msg_hash, &signature, pub_key).map_err(ProofError::from)
    }
}

#[cfg(feature = "zkvm-native-crypto")]
fn verify_command_signature_native(
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
        .verify(&native_command_message(packed_command), &signature)
        .is_ok())
}

#[cfg(feature = "zkvm-native-crypto")]
pub fn native_sign_command_for_testing(
    formatted_priv_key: &Field,
    packed_command: &[Field; 3],
) -> ([Field; 2], Field) {
    let key_material = native_key_material(formatted_priv_key);
    let signature = key_material
        .signing_key
        .sign(&native_command_message(packed_command));
    split_ed25519_signature(signature.to_bytes())
}

#[cfg(feature = "zkvm-native-crypto")]
struct NativeKeyMaterial {
    signing_key: SigningKey,
    x25519_secret: X25519StaticSecret,
    pub_key: [Field; 2],
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_key_material(formatted_priv_key: &Field) -> NativeKeyMaterial {
    let signing_key = SigningKey::from_bytes(&native_private_key_seed(formatted_priv_key));
    let x25519_secret = X25519StaticSecret::from(native_x25519_secret_seed(formatted_priv_key));
    let ed_pub = BigUint::from_bytes_be(&signing_key.verifying_key().to_bytes());
    let x_pub = BigUint::from_bytes_be(&X25519PublicKey::from(&x25519_secret).to_bytes());
    NativeKeyMaterial {
        signing_key,
        x25519_secret,
        pub_key: [ed_pub, x_pub],
    }
}

#[cfg(feature = "zkvm-native-crypto")]
fn ecdh_formatted_priv_key_native(
    formatted_priv_key: &Field,
    pub_key: &[Field; 2],
) -> ProofResult<[Field; 2]> {
    if pub_key[1].is_zero() {
        return Ok([BigUint::from(0u32), BigUint::one()]);
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
        BigUint::from_bytes_be(&digest[0..16]),
        BigUint::from_bytes_be(&digest[16..32]),
    ])
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_private_key_seed(formatted_priv_key: &Field) -> [u8; 32] {
    native_seed(b"AMACI_ZKVM_NATIVE_ED25519_SEED_V1", formatted_priv_key)
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_x25519_secret_seed(formatted_priv_key: &Field) -> [u8; 32] {
    native_seed(b"AMACI_ZKVM_NATIVE_X25519_SEED_V1", formatted_priv_key)
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_seed(domain: &[u8], formatted_priv_key: &Field) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(field_to_fixed_be_lossy(formatted_priv_key));
    hasher.finalize().into()
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_command_message(packed_command: &[Field; 3]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"AMACI_ZKVM_NATIVE_COMMAND_V1");
    for element in packed_command {
        hasher.update(field_to_fixed_be_lossy(element));
    }
    hasher.finalize().into()
}

#[cfg(feature = "zkvm-native-crypto")]
fn split_ed25519_signature(bytes: [u8; 64]) -> ([Field; 2], Field) {
    (
        [
            BigUint::from_bytes_be(&bytes[0..22]),
            BigUint::from_bytes_be(&bytes[22..43]),
        ],
        BigUint::from_bytes_be(&bytes[43..64]),
    )
}

#[cfg(feature = "zkvm-native-crypto")]
fn join_ed25519_signature(r8: &[Field; 2], s: &Field) -> ProofResult<[u8; 64]> {
    let mut bytes = [0u8; 64];
    write_fixed_be(&mut bytes[0..22], &r8[0], "Ed25519 signature chunk 0")?;
    write_fixed_be(&mut bytes[22..43], &r8[1], "Ed25519 signature chunk 1")?;
    write_fixed_be(&mut bytes[43..64], s, "Ed25519 signature chunk 2")?;
    Ok(bytes)
}

#[cfg(feature = "zkvm-native-crypto")]
fn pub_key_ed25519(pub_key: &[Field; 2]) -> &Field {
    &pub_key[0]
}

#[cfg(feature = "zkvm-native-crypto")]
fn pub_key_x25519(pub_key: &[Field; 2]) -> &Field {
    &pub_key[1]
}

#[cfg(feature = "zkvm-native-crypto")]
fn field_to_fixed_be(value: &Field, name: &'static str) -> ProofResult<[u8; 32]> {
    let mut out = [0u8; 32];
    write_fixed_be(&mut out, value, name)?;
    Ok(out)
}

#[cfg(feature = "zkvm-native-crypto")]
fn write_fixed_be(out: &mut [u8], value: &Field, name: &'static str) -> ProofResult<()> {
    let bytes = value.to_bytes_be();
    if bytes.len() > out.len() {
        return Err(ProofError::InvalidLength {
            name,
            expected: out.len(),
            actual: bytes.len(),
        });
    }
    out.fill(0);
    let offset = out.len() - bytes.len();
    out[offset..].copy_from_slice(&bytes);
    Ok(())
}

#[cfg(feature = "zkvm-native-crypto")]
fn field_to_fixed_be_lossy(value: &Field) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        out[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

/// Mirrors `amaci/power/lib/rerandomize.circom::ElGamalDecrypt`.
pub fn elgamal_decrypt_x_and_odd(
    c1: &[Field; 2],
    c2: &[Field; 2],
    formatted_priv_key: &Field,
) -> ProofResult<(Field, bool)> {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        return elgamal_decrypt_x_and_odd_native(c1, c2, formatted_priv_key);
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        let c1x = scalar_mul_any_253_circom(c1, formatted_priv_key)?;
        let c1x_inverse = [f_neg(&c1x[0]), c1x[1].clone()];
        let decrypted = baby_add_circom(&c1x_inverse, c2)?;
        let x = decrypted[0].clone();
        let is_odd = x.bit(0);
        Ok((x, is_odd))
    }
}

#[cfg(feature = "zkvm-native-crypto")]
fn elgamal_decrypt_x_and_odd_native(
    c1: &[Field; 2],
    c2: &[Field; 2],
    formatted_priv_key: &Field,
) -> ProofResult<(Field, bool)> {
    if c1.iter().all(Zero::is_zero) && c2.iter().all(Zero::is_zero) {
        return Ok((BigUint::from(0u32), false));
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

// Mirrors `amaci/power/lib/rerandomize.circom::ElGamalDecrypt`.
// Circomlib's `EscalarMulAny(253)` uses Montgomery segment formulas and treats
// zero-x input as the identity output. Arkworks curve multiplication panics for
// those witness values, so ElGamal decryption needs this algebraic path.
#[cfg(not(feature = "zkvm-native-crypto"))]
fn scalar_mul_any_253_circom(point: &[Field; 2], scalar: &Field) -> ProofResult<[Field; 2]> {
    if scalar > elgamal_privkey_max() {
        return Err(ProofError::InvalidRange {
            name: "ElGamal privKey",
            value: scalar.clone(),
            max: elgamal_privkey_max().clone(),
        });
    }

    let bits = bits_le(scalar, 253);
    let zero_point = point[0].is_zero();
    let first_point = if zero_point { base8_circom() } else { point };

    let first = segment_mul_any_circom(&bits[0..148], first_point)?;
    let doubled = montgomery_double(&first.dbl)?;
    let second_point = montgomery_to_edwards(&doubled)?;
    let second = segment_mul_any_circom(&bits[148..253], &second_point)?;
    let combined = baby_add_circom(&first.out, &second.out)?;

    if zero_point {
        Ok([BigUint::from(0u32), BigUint::one()])
    } else {
        Ok(combined)
    }
}

#[cfg(not(feature = "zkvm-native-crypto"))]
struct SegmentOutput {
    out: [Field; 2],
    dbl: [Field; 2],
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn segment_mul_any_circom(bits: &[bool], point: &[Field; 2]) -> ProofResult<SegmentOutput> {
    debug_assert!(bits.len() >= 2);
    let p_mont = edwards_to_montgomery(point)?;
    let mut dbl_in = p_mont.clone();
    let mut add_in = p_mont;

    for bit in bits.iter().skip(1) {
        let dbl_out = montgomery_double(&dbl_in)?;
        let add_out = montgomery_add(&dbl_out, &add_in)?;
        add_in = if *bit { add_out } else { add_in };
        dbl_in = dbl_out;
    }

    let m2e = montgomery_to_edwards(&add_in)?;
    let negative_point = [f_neg(&point[0]), point[1].clone()];
    let without_low_bit = baby_add_circom(&m2e, &negative_point)?;
    let out = if bits[0] { m2e } else { without_low_bit };
    Ok(SegmentOutput { out, dbl: dbl_in })
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn bits_le(value: &Field, len: usize) -> Vec<bool> {
    (0..len).map(|i| value.bit(i as u64)).collect()
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn baby_add_circom(p1: &[Field; 2], p2: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let a = BigUint::from(168700u32);
    let d = BigUint::from(168696u32);
    let beta = f_mul(&p1[0], &p2[1]);
    let gamma = f_mul(&p1[1], &p2[0]);
    let delta = f_mul(
        &f_add(&f_neg(&f_mul(&a, &p1[0])), &p1[1]),
        &f_add(&p2[0], &p2[1]),
    );
    let tau = f_mul(&beta, &gamma);
    let x = f_div(
        &f_add(&beta, &gamma),
        &f_add(&BigUint::one(), &f_mul(&d, &tau)),
    )?;
    let y_num = f_sub(&f_add(&delta, &f_mul(&a, &beta)), &gamma);
    let y = f_div(&y_num, &f_sub(&BigUint::one(), &f_mul(&d, &tau)))?;
    Ok([x, y])
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn edwards_to_montgomery(point: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let u = f_div(
        &f_add(&BigUint::one(), &point[1]),
        &f_sub(&BigUint::one(), &point[1]),
    )?;
    let v = f_div(&u, &point[0])?;
    Ok([u, v])
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn montgomery_to_edwards(point: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let x = f_div(&point[0], &point[1])?;
    let y = f_div(
        &f_sub(&point[0], &BigUint::one()),
        &f_add(&point[0], &BigUint::one()),
    )?;
    Ok([x, y])
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn montgomery_add(p1: &[Field; 2], p2: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let a = BigUint::from(168700u32);
    let d = BigUint::from(168696u32);
    let curve_a = f_div(&f_mul(&BigUint::from(2u32), &f_add(&a, &d)), &f_sub(&a, &d))?;
    let curve_b = f_div(&BigUint::from(4u32), &f_sub(&a, &d))?;
    let lambda = f_div(&f_sub(&p2[1], &p1[1]), &f_sub(&p2[0], &p1[0]))?;
    let x = f_sub(
        &f_sub(
            &f_sub(&f_mul(&curve_b, &f_mul(&lambda, &lambda)), &curve_a),
            &p1[0],
        ),
        &p2[0],
    );
    let y = f_sub(&f_mul(&lambda, &f_sub(&p1[0], &x)), &p1[1]);
    Ok([x, y])
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn montgomery_double(point: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let a = BigUint::from(168700u32);
    let d = BigUint::from(168696u32);
    let curve_a = f_div(&f_mul(&BigUint::from(2u32), &f_add(&a, &d)), &f_sub(&a, &d))?;
    let curve_b = f_div(&BigUint::from(4u32), &f_sub(&a, &d))?;
    let x_squared = f_mul(&point[0], &point[0]);
    let numerator = f_add(
        &f_add(
            &f_mul(&BigUint::from(3u32), &x_squared),
            &f_mul(&f_mul(&BigUint::from(2u32), &curve_a), &point[0]),
        ),
        &BigUint::one(),
    );
    let denominator = f_mul(&f_mul(&BigUint::from(2u32), &curve_b), &point[1]);
    let lambda = f_div(&numerator, &denominator)?;
    let x = f_sub(
        &f_sub(&f_mul(&curve_b, &f_mul(&lambda, &lambda)), &curve_a),
        &f_mul(&BigUint::from(2u32), &point[0]),
    );
    let y = f_sub(&f_mul(&lambda, &f_sub(&point[0], &x)), &point[1]);
    Ok([x, y])
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn f_add(a: &Field, b: &Field) -> Field {
    (a + b) % &*SNARK_FIELD_SIZE
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn f_sub(a: &Field, b: &Field) -> Field {
    sub(a, b)
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn f_mul(a: &Field, b: &Field) -> Field {
    (a * b) % &*SNARK_FIELD_SIZE
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn f_neg(a: &Field) -> Field {
    if a.is_zero() {
        BigUint::from(0u32)
    } else {
        sub(&BigUint::from(0u32), a)
    }
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn f_div(numerator: &Field, denominator: &Field) -> ProofResult<Field> {
    if denominator.is_zero() {
        return Err(ProofError::Crypto(
            "division by zero in BabyJubJub formula".to_string(),
        ));
    }
    let inverse = denominator.modpow(field_minus_two(), &SNARK_FIELD_SIZE);
    Ok(f_mul(numerator, &inverse))
}

/// Mirrors `utils/lib/poseidonDecrypt.circom::PoseidonDecryptWithoutCheck`.
pub fn poseidon_decrypt_without_check(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<Vec<Field>> {
    #[cfg(feature = "zkvm-native-crypto")]
    {
        return native_decrypt_without_check(ciphertext, key, nonce, len);
    }

    #[cfg(not(feature = "zkvm-native-crypto"))]
    {
        let mut decrypted_len = len;
        while decrypted_len % 3 != 0 {
            decrypted_len += 1;
        }
        if ciphertext.len() != decrypted_len + 1 {
            return Err(ProofError::InvalidLength {
                name: "poseidon ciphertext",
                expected: decrypted_len + 1,
                actual: ciphertext.len(),
            });
        }
        if nonce >= &(BigUint::one() << 128usize) {
            return Err(ProofError::InvalidRange {
                name: "poseidon nonce",
                value: nonce.clone(),
                max: (BigUint::one() << 128usize) - BigUint::one(),
            });
        }

        let n = (decrypted_len + 1) / 3;
        let two128 = BigUint::one() << 128usize;
        let mut state = poseidon_perm4(&[
            BigUint::zero(),
            key[0].clone(),
            key[1].clone(),
            nonce + &(BigUint::from(len) * &two128),
        ])?;

        let mut decrypted = vec![BigUint::zero(); decrypted_len];
        for i in 0..n {
            for j in 0..3 {
                decrypted[i * 3 + j] = sub(&ciphertext[i * 3 + j], &state[j + 1]);
            }
            state = poseidon_perm4(&[
                state[0].clone(),
                ciphertext[i * 3].clone(),
                ciphertext[i * 3 + 1].clone(),
                ciphertext[i * 3 + 2].clone(),
            ])?;
        }
        Ok(decrypted)
    }
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_decrypt_without_check(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<Vec<Field>> {
    let decrypted_len = padded_decrypt_len(len);
    if ciphertext.len() != decrypted_len + 1 {
        return Err(ProofError::InvalidLength {
            name: "poseidon ciphertext",
            expected: decrypted_len + 1,
            actual: ciphertext.len(),
        });
    }
    validate_poseidon_nonce(nonce)?;

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

#[cfg(feature = "zkvm-native-crypto")]
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
    validate_poseidon_nonce(nonce)?;

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

#[cfg(feature = "zkvm-native-crypto")]
fn native_decrypt_stream_prefix(key: &[Field; 2], nonce: &Field, len: usize) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"AMACI_ZKVM_NATIVE_DECRYPT_STREAM_V1");
    hasher.update(field_to_fixed_be_lossy(&key[0]));
    hasher.update(field_to_fixed_be_lossy(&key[1]));
    hasher.update(field_to_fixed_be_lossy(nonce));
    hasher.update((len as u64).to_be_bytes());
    hasher
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_decrypt_stream_word(stream_prefix: &Sha256, index: usize) -> [u8; 32] {
    let mut hasher = stream_prefix.clone();
    hasher.update((index as u64).to_be_bytes());
    hasher.finalize().into()
}

#[cfg(feature = "zkvm-native-crypto")]
fn native_stream_xor(value: &Field, stream_word: &[u8; 32]) -> Field {
    let mut value_bytes = field_to_fixed_be_lossy(value);
    for (byte, stream_byte) in value_bytes.iter_mut().zip(stream_word) {
        *byte ^= stream_byte;
    }
    BigUint::from_bytes_be(&value_bytes)
}

#[cfg(feature = "zkvm-native-crypto")]
fn padded_decrypt_len(len: usize) -> usize {
    let mut decrypted_len = len;
    while decrypted_len % 3 != 0 {
        decrypted_len += 1;
    }
    decrypted_len
}

#[cfg(feature = "zkvm-native-crypto")]
fn validate_poseidon_nonce(nonce: &Field) -> ProofResult<()> {
    if nonce >= &(BigUint::one() << 128usize) {
        return Err(ProofError::InvalidRange {
            name: "poseidon nonce",
            value: nonce.clone(),
            max: (BigUint::one() << 128usize) - BigUint::one(),
        });
    }
    Ok(())
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn poseidon_perm4(inputs: &[Field; 4]) -> ProofResult<[Field; 4]> {
    let params = bn254_x5::get_poseidon_parameters::<Fr>(4)
        .map_err(|e| ProofError::Crypto(e.to_string()))?;
    let state = [
        field_to_fr(&inputs[0]),
        field_to_fr(&inputs[1]),
        field_to_fr(&inputs[2]),
        field_to_fr(&inputs[3]),
    ];
    let out = poseidon_permutation(state, &params);
    Ok(out.map(fr_to_field))
}

#[cfg(not(feature = "zkvm-native-crypto"))]
fn poseidon_permutation<const T: usize>(
    mut state: [Fr; T],
    params: &PoseidonParameters<Fr>,
) -> [Fr; T] {
    let all_rounds = params.full_rounds + params.partial_rounds;
    let half_rounds = params.full_rounds / 2;

    for round in 0..all_rounds {
        for i in 0..T {
            state[i] += params.ark[round * params.width + i];
        }

        if round < half_rounds || round >= half_rounds + params.partial_rounds {
            for value in state.iter_mut() {
                *value = value.pow([params.alpha]);
            }
        } else {
            state[0] = state[0].pow([params.alpha]);
        }

        let mut mixed = [Fr::from(0u64); T];
        for i in 0..T {
            for j in 0..T {
                mixed[i] += state[j] * params.mds[i][j];
            }
        }
        state = mixed;
    }

    state
}
