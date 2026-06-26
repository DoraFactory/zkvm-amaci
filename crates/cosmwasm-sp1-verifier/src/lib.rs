pub mod contract;
pub mod error;
pub mod msg;

pub use crate::contract::verify_sp1_groth16;

#[cfg(target_arch = "wasm32")]
mod wasm_getrandom {
    use core::num::NonZeroU32;

    use getrandom::{register_custom_getrandom, Error};

    const UNSUPPORTED_RANDOM_CODE: u32 = Error::CUSTOM_START + 1;

    pub fn reject_random(_: &mut [u8]) -> Result<(), Error> {
        let code = NonZeroU32::new(UNSUPPORTED_RANDOM_CODE).expect("non-zero custom error code");
        Err(Error::from(code))
    }

    register_custom_getrandom!(reject_random);
}
