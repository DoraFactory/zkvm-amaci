use crate::error::{ProofError, ProofResult};
use num_traits::{One, Zero};
use ruint::aliases::U256;

pub type Field = U256;

pub fn zero() -> Field {
    Field::zero()
}

pub fn one() -> Field {
    Field::one()
}

pub fn field(value: u128) -> Field {
    Field::from(value)
}

pub fn add(a: &Field, b: &Field) -> Field {
    *a + *b
}

pub fn sub(a: &Field, b: &Field) -> Field {
    if a >= b {
        *a - *b
    } else {
        Field::zero()
    }
}

pub fn mul(a: &Field, b: &Field) -> Field {
    *a * *b
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
