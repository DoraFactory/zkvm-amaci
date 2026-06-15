use crate::error::{ProofError, ProofResult};
use crate::field::{sub, Field};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field as ArkField, PrimeField, Zero};
use baby_jubjub::{base8, mul_point_escalar, EdFr, EdwardsAffine, Fq};
use eddsa_poseidon::Signature;
use light_poseidon::parameters::bn254_x5;
use light_poseidon::PoseidonParameters;
use maci_crypto::keys::verify_signature_eddsa;
use maci_crypto::{poseidon, SNARK_FIELD_SIZE};
use num_bigint::BigUint;
use num_traits::One;

fn field_to_fr(value: &Field) -> Fr {
    Fr::from_le_bytes_mod_order(&(value % &*SNARK_FIELD_SIZE).to_bytes_le())
}

fn fr_to_field(value: Fr) -> Field {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le())
}

fn field_to_edfr(value: &Field) -> EdFr {
    EdFr::from_le_bytes_mod_order(&value.to_bytes_le())
}

fn pubkey_to_point(pub_key: &[Field; 2]) -> EdwardsAffine {
    let x = Fq::from_le_bytes_mod_order(&pub_key[0].to_bytes_le());
    let y = Fq::from_le_bytes_mod_order(&pub_key[1].to_bytes_le());
    EdwardsAffine::new_unchecked(x, y)
}

fn point_to_pubkey(point: EdwardsAffine) -> [Field; 2] {
    [
        BigUint::from_bytes_le(&point.x.into_bigint().to_bytes_le()),
        BigUint::from_bytes_le(&point.y.into_bigint().to_bytes_le()),
    ]
}

/// Mirrors `utils/privToPubKey.circom::PrivToPubKey`.
pub fn private_to_pub_key(formatted_priv_key: &Field) -> [Field; 2] {
    let scalar = field_to_edfr(formatted_priv_key);
    point_to_pubkey(mul_point_escalar(&base8(), scalar))
}

/// Mirrors `utils/ecdh.circom::Ecdh`.
pub fn ecdh_formatted_priv_key(formatted_priv_key: &Field, pub_key: &[Field; 2]) -> [Field; 2] {
    if pub_key[0].is_zero() {
        return [BigUint::from(0u32), BigUint::one()];
    }
    let scalar = field_to_edfr(formatted_priv_key);
    point_to_pubkey(mul_point_escalar(&pubkey_to_point(pub_key), scalar))
}

/// Mirrors `utils/verifySignature.circom::VerifySignature`.
pub fn verify_command_signature(
    pub_key: &[Field; 2],
    r8: &[Field; 2],
    s: &Field,
    packed_command: &[Field; 3],
) -> ProofResult<bool> {
    let msg_hash = poseidon(packed_command);
    let signature = Signature {
        r8: pubkey_to_point(r8),
        s: s.clone(),
    };
    verify_signature_eddsa(&msg_hash, &signature, pub_key).map_err(ProofError::from)
}

/// Mirrors `amaci/power/lib/rerandomize.circom::ElGamalDecrypt`.
pub fn elgamal_decrypt_x_and_odd(
    c1: &[Field; 2],
    c2: &[Field; 2],
    formatted_priv_key: &Field,
) -> ProofResult<(Field, bool)> {
    let c1x = scalar_mul_any_253_circom(c1, formatted_priv_key)?;
    let c1x_inverse = [f_neg(&c1x[0]), c1x[1].clone()];
    let decrypted = baby_add_circom(&c1x_inverse, c2)?;
    let x = decrypted[0].clone();
    let is_odd = (&x & BigUint::one()) == BigUint::one();
    Ok((x, is_odd))
}

// Mirrors `amaci/power/lib/rerandomize.circom::ElGamalDecrypt`.
// Circomlib's `EscalarMulAny(253)` uses Montgomery segment formulas and treats
// zero-x input as the identity output. Arkworks curve multiplication panics for
// those witness values, so ElGamal decryption needs this algebraic path.
fn scalar_mul_any_253_circom(point: &[Field; 2], scalar: &Field) -> ProofResult<[Field; 2]> {
    if scalar >= &(BigUint::one() << 253usize) {
        return Err(ProofError::InvalidRange {
            name: "ElGamal privKey",
            value: scalar.clone(),
            max: (BigUint::one() << 253usize) - BigUint::one(),
        });
    }

    let bits = bits_le(scalar, 253);
    let zero_point = point[0].is_zero();
    let base8 = [
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
    ];
    let first_point = if zero_point { &base8 } else { point };

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

struct SegmentOutput {
    out: [Field; 2],
    dbl: [Field; 2],
}

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

fn bits_le(value: &Field, len: usize) -> Vec<bool> {
    (0..len)
        .map(|i| ((value >> i) & BigUint::one()) == BigUint::one())
        .collect()
}

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

fn edwards_to_montgomery(point: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let u = f_div(
        &f_add(&BigUint::one(), &point[1]),
        &f_sub(&BigUint::one(), &point[1]),
    )?;
    let v = f_div(&u, &point[0])?;
    Ok([u, v])
}

fn montgomery_to_edwards(point: &[Field; 2]) -> ProofResult<[Field; 2]> {
    let x = f_div(&point[0], &point[1])?;
    let y = f_div(
        &f_sub(&point[0], &BigUint::one()),
        &f_add(&point[0], &BigUint::one()),
    )?;
    Ok([x, y])
}

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

fn f_add(a: &Field, b: &Field) -> Field {
    (a + b) % &*SNARK_FIELD_SIZE
}

fn f_sub(a: &Field, b: &Field) -> Field {
    sub(a, b)
}

fn f_mul(a: &Field, b: &Field) -> Field {
    (a * b) % &*SNARK_FIELD_SIZE
}

fn f_neg(a: &Field) -> Field {
    if a.is_zero() {
        BigUint::from(0u32)
    } else {
        sub(&BigUint::from(0u32), a)
    }
}

fn f_div(numerator: &Field, denominator: &Field) -> ProofResult<Field> {
    if denominator.is_zero() {
        return Err(ProofError::Crypto(
            "division by zero in BabyJubJub formula".to_string(),
        ));
    }
    let inverse = denominator.modpow(
        &(&*SNARK_FIELD_SIZE - BigUint::from(2u32)),
        &SNARK_FIELD_SIZE,
    );
    Ok(f_mul(numerator, &inverse))
}

/// Mirrors `utils/lib/poseidonDecrypt.circom::PoseidonDecryptWithoutCheck`.
pub fn poseidon_decrypt_without_check(
    ciphertext: &[Field],
    key: &[Field; 2],
    nonce: &Field,
    len: usize,
) -> ProofResult<Vec<Field>> {
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

        let mut mixed = [Fr::zero(); T];
        for i in 0..T {
            for j in 0..T {
                mixed[i] += state[j] * params.mds[i][j];
            }
        }
        state = mixed;
    }

    state
}
