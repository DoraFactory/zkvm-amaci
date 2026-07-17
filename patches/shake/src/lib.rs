#![no_std]

//! Compatibility adapter for RustCrypto's standalone `shake` crate.
//!
//! ML-DSA depends on `shake 0.1`, while SP1 accelerates the SHAKE types in
//! RustCrypto's `sha3 0.11` crate. Both implement FIPS 202 through the same
//! `digest 0.11` traits, so re-exporting the accelerated types preserves the
//! public API and wire semantics without maintaining another hash backend.

pub use sha3::digest;
pub use sha3::digest::{ExtendableOutput, Update, XofReader};
pub use sha3::{Shake128, Shake128Reader, Shake256, Shake256Reader};
