use crate::error::{ProofError, ProofResult};
use maci_crypto::SNARK_FIELD_SIZE;
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub type Field = BigUint;

pub fn zero() -> Field {
    Field::zero()
}

pub fn one() -> Field {
    Field::one()
}

pub fn field(value: impl Into<Field>) -> Field {
    value.into() % &*SNARK_FIELD_SIZE
}

pub fn add(a: &Field, b: &Field) -> Field {
    (a + b) % &*SNARK_FIELD_SIZE
}

pub fn sub(a: &Field, b: &Field) -> Field {
    if a >= b {
        (a - b) % &*SNARK_FIELD_SIZE
    } else {
        (&*SNARK_FIELD_SIZE - ((b - a) % &*SNARK_FIELD_SIZE)) % &*SNARK_FIELD_SIZE
    }
}

pub fn mul(a: &Field, b: &Field) -> Field {
    (a * b) % &*SNARK_FIELD_SIZE
}

pub fn pow5(base: usize, exp: usize) -> usize {
    base.pow(exp as u32)
}

pub fn two_pow(bits: usize) -> Field {
    Field::one() << bits
}

pub fn ensure_equal(name: &'static str, expected: &Field, actual: &Field) -> ProofResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProofError::CommitmentMismatch {
            name,
            expected: expected.clone(),
            actual: actual.clone(),
        })
    }
}

pub fn ensure_bits(name: &'static str, value: &Field, bits: usize) -> ProofResult<()> {
    let max = two_pow(bits);
    if value < &max {
        Ok(())
    } else {
        Err(ProofError::InvalidRange {
            name,
            value: value.clone(),
            max: max - Field::one(),
        })
    }
}

pub fn ensure_bool(name: &'static str, value: &Field) -> ProofResult<()> {
    if value.is_zero() || value == &Field::one() {
        Ok(())
    } else {
        Err(ProofError::InvalidBoolean {
            name,
            value: value.clone(),
        })
    }
}
