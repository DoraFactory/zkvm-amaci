use crate::constants::{biguint_to_fr, fr_to_biguint, SNARK_FIELD_SIZE};
use crate::error::{CryptoError, Result};
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

fn field_to_fr(value: &BigUint) -> Fr {
    biguint_to_fr(&(value % &*SNARK_FIELD_SIZE))
}

fn poseidon_fr_inputs(fr_inputs: &[Fr]) -> BigUint {
    if fr_inputs.is_empty() {
        return BigUint::from(0u32);
    }

    let mut poseidon =
        Poseidon::<Fr>::new_circom(fr_inputs.len()).expect("Failed to create Poseidon hasher");
    let result_fr = poseidon.hash(fr_inputs).expect("Poseidon hash failed");
    fr_to_biguint(&result_fr)
}

fn poseidon_refs(inputs: &[&BigUint]) -> BigUint {
    let fr_inputs: Vec<Fr> = inputs.iter().map(|value| field_to_fr(value)).collect();
    poseidon_fr_inputs(&fr_inputs)
}

fn poseidon_padded(num_elements: usize, elements: &[BigUint]) -> Result<BigUint> {
    if elements.len() > num_elements {
        return Err(CryptoError::HashElementsExceedMax {
            actual: elements.len(),
            max: num_elements,
        });
    }

    let mut fr_inputs = Vec::with_capacity(num_elements);
    fr_inputs.extend(elements.iter().map(field_to_fr));
    fr_inputs.resize(num_elements, Fr::from(0u64));

    Ok(poseidon_fr_inputs(&fr_inputs))
}

/// Main Poseidon hash function
/// Hashes an array of BigUint values using Poseidon with Circom-compatible parameters
pub fn poseidon(inputs: &[BigUint]) -> BigUint {
    let fr_inputs: Vec<Fr> = inputs.iter().map(field_to_fr).collect();
    poseidon_fr_inputs(&fr_inputs)
}

/// Hash exactly 2 elements using Poseidon
pub fn poseidon_t3(inputs: &[BigUint]) -> Result<BigUint> {
    if inputs.len() != 2 {
        return Err(CryptoError::PoseidonInputCountMismatch {
            expected: 2,
            actual: inputs.len(),
        });
    }
    Ok(poseidon(inputs))
}

/// Hash exactly 3 elements using Poseidon
pub fn poseidon_t4(inputs: &[BigUint]) -> Result<BigUint> {
    if inputs.len() != 3 {
        return Err(CryptoError::PoseidonInputCountMismatch {
            expected: 3,
            actual: inputs.len(),
        });
    }
    Ok(poseidon(inputs))
}

/// Hash exactly 4 elements using Poseidon
pub fn poseidon_t5(inputs: &[BigUint]) -> Result<BigUint> {
    if inputs.len() != 4 {
        return Err(CryptoError::PoseidonInputCountMismatch {
            expected: 4,
            actual: inputs.len(),
        });
    }
    Ok(poseidon(inputs))
}

/// Hash exactly 5 elements using Poseidon
pub fn poseidon_t6(inputs: &[BigUint]) -> Result<BigUint> {
    if inputs.len() != 5 {
        return Err(CryptoError::PoseidonInputCountMismatch {
            expected: 5,
            actual: inputs.len(),
        });
    }
    Ok(poseidon(inputs))
}

/// Hash two BigUints (convenience function for Merkle trees)
pub fn hash_left_right(left: &BigUint, right: &BigUint) -> BigUint {
    poseidon_refs(&[left, right])
}

/// Hash up to N elements, padding with zeros if necessary
pub fn hash_n(num_elements: usize, elements: &[BigUint]) -> Result<BigUint> {
    poseidon_padded(num_elements, elements)
}

/// Hash 2 elements
pub fn hash2(elements: &[BigUint]) -> Result<BigUint> {
    hash_n(2, elements)
}

/// Hash 3 elements
pub fn hash3(elements: &[BigUint]) -> Result<BigUint> {
    hash_n(3, elements)
}

/// Hash 4 elements
pub fn hash4(elements: &[BigUint]) -> Result<BigUint> {
    hash_n(4, elements)
}

/// Hash 5 elements
pub fn hash5(elements: &[BigUint]) -> Result<BigUint> {
    hash_n(5, elements)
}

/// Hash for LeanIMT (same as hash2)
pub fn hash_lean_imt(a: &BigUint, b: &BigUint) -> BigUint {
    hash_left_right(a, b)
}

/// Hash exactly 10 elements using the structure: hash2(hash5(first 5), hash5(last 5))
pub fn hash10(elements: &[BigUint]) -> Result<BigUint> {
    const MAX: usize = 10;

    if elements.len() > MAX {
        return Err(CryptoError::HashElementsExceedMax {
            actual: elements.len(),
            max: MAX,
        });
    }

    let first_end = elements.len().min(5);
    let hash1 = poseidon_padded(5, &elements[..first_end])?;
    let hash2_val = if elements.len() > 5 {
        poseidon_padded(5, &elements[5..])?
    } else {
        poseidon_padded(5, &[])?
    };

    Ok(poseidon_refs(&[&hash1, &hash2_val]))
}

/// Hash up to 12 elements
pub fn hash12(elements: &[BigUint]) -> Result<BigUint> {
    const MAX: usize = 12;

    if elements.len() > MAX {
        return Err(CryptoError::HashElementsExceedMax {
            actual: elements.len(),
            max: MAX,
        });
    }

    let first_end = elements.len().min(5);
    let hash1 = poseidon_padded(5, &elements[..first_end])?;
    let hash2_val = if elements.len() > 5 {
        let second_end = elements.len().min(10);
        poseidon_padded(5, &elements[5..second_end])?
    } else {
        poseidon_padded(5, &[])?
    };
    let zero = BigUint::from(0u32);
    let element10 = elements.get(10).unwrap_or(&zero);
    let element11 = elements.get(11).unwrap_or(&zero);

    Ok(poseidon_refs(&[&hash1, &hash2_val, element10, element11]))
}

/// Hash a single BigUint
pub fn hash_one(pre_image: &BigUint) -> BigUint {
    poseidon_padded(2, std::slice::from_ref(pre_image)).expect("hash_one input fits arity 2")
}

/// EVM-compatible SHA256 hash for uint256 array
/// Used for computing input hashes for zkSNARK circuits
pub fn sha256_hash(inputs: &[BigUint]) -> BigUint {
    let mut hasher = Sha256::new();

    for input in inputs {
        let bytes = input.to_bytes_be();
        let mut word = [0u8; 32];
        if bytes.len() > 32 {
            hasher.update(&bytes);
            continue;
        } else if bytes.len() == 32 {
            word.copy_from_slice(&bytes);
        } else {
            word[32 - bytes.len()..].copy_from_slice(&bytes);
        }
        hasher.update(word);
    }

    let result = hasher.finalize();
    let hash_value = BigUint::from_bytes_be(&result);
    &hash_value % &*SNARK_FIELD_SIZE
}

/// Compute input hash for zkSNARK circuits using EVM-compatible packed sha256
/// This is a unified function used across MACI circuits for computing input hashes
pub fn compute_input_hash(values: &[BigUint]) -> BigUint {
    sha256_hash(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_basic() {
        let inputs = vec![BigUint::from(1u32), BigUint::from(2u32)];
        let result = poseidon(&inputs);
        // Just verify it produces a result in the field
        assert!(result < *SNARK_FIELD_SIZE);
        assert_ne!(result, BigUint::from(0u32));
    }

    #[test]
    fn test_poseidon_t3() {
        let inputs = vec![BigUint::from(1u32), BigUint::from(2u32)];
        let result = poseidon_t3(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_poseidon_t3_wrong_length() {
        let inputs = vec![BigUint::from(1u32)];
        let result = poseidon_t3(&inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_left_right() {
        let left = BigUint::from(100u32);
        let right = BigUint::from(200u32);
        let result = hash_left_right(&left, &right);
        assert!(result < *SNARK_FIELD_SIZE);
        assert_ne!(result, BigUint::from(0u32));
    }

    #[test]
    fn test_hash_n_padding() {
        let inputs = vec![BigUint::from(1u32)];
        let result = hash_n(2, &inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash2() {
        let inputs = vec![BigUint::from(1u32), BigUint::from(2u32)];
        let result = hash2(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash5() {
        let inputs = vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
        ];
        let result = hash5(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash10() {
        let inputs: Vec<BigUint> = (1u32..=8).map(BigUint::from).collect();
        let result = hash10(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash12() {
        let inputs: Vec<BigUint> = (1u32..=10).map(BigUint::from).collect();
        let result = hash12(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_one() {
        let value = BigUint::from(12345u32);
        let result = hash_one(&value);
        assert!(result < *SNARK_FIELD_SIZE);
    }

    #[test]
    fn test_sha256_hash() {
        let inputs = vec![BigUint::from(1u32), BigUint::from(2u32)];
        let result = sha256_hash(&inputs);
        assert!(result < *SNARK_FIELD_SIZE);
    }

    #[test]
    fn test_compute_input_hash() {
        let inputs = vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
        ];
        let result = compute_input_hash(&inputs);
        assert!(result < *SNARK_FIELD_SIZE);
    }

    #[test]
    fn test_poseidon_deterministic() {
        let inputs = vec![BigUint::from(1u32), BigUint::from(2u32)];
        let result1 = poseidon(&inputs);
        let result2 = poseidon(&inputs);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_poseidon_empty() {
        let inputs = vec![];
        let result = poseidon(&inputs);
        assert_eq!(result, BigUint::from(0u32));
    }

    #[test]
    fn test_hash_avalanche_effect() {
        let inputs1 = vec![BigUint::from(1u32), BigUint::from(2u32)];
        let inputs2 = vec![BigUint::from(1u32), BigUint::from(3u32)];

        let result1 = poseidon(&inputs1);
        let result2 = poseidon(&inputs2);

        assert_ne!(result1, result2);
    }
}
