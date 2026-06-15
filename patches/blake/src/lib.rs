use blake2::{Blake2b512, Digest};
use std::error::Error;
use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, BlakeError>;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum BlakeError {
    Fail,
    BadHashbitlen,
}

impl fmt::Display for BlakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlakeError::Fail => write!(f, "BLAKE hashing failed"),
            BlakeError::BadHashbitlen => write!(f, "invalid BLAKE hash length"),
        }
    }
}

impl Error for BlakeError {}

pub fn hash(hashbitlen: i32, data: &[u8], hashval: &mut [u8]) -> Result<()> {
    write_digest(hashbitlen, data, hashval)
}

pub struct Blake {
    hashbitlen: i32,
    data: Vec<u8>,
}

impl Blake {
    pub fn new(hashbitlen: i32) -> Result<Self> {
        validate_hashbitlen(hashbitlen)?;
        Ok(Self {
            hashbitlen,
            data: Vec::new(),
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn finalise(&mut self, hashval: &mut [u8]) {
        write_digest(self.hashbitlen, &self.data, hashval).expect("validated BLAKE hash length");
    }
}

impl io::Write for Blake {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_hashbitlen(hashbitlen: i32) -> Result<usize> {
    match hashbitlen {
        224 | 256 | 384 | 512 => Ok((hashbitlen / 8) as usize),
        _ => Err(BlakeError::BadHashbitlen),
    }
}

fn write_digest(hashbitlen: i32, data: &[u8], hashval: &mut [u8]) -> Result<()> {
    let out_len = validate_hashbitlen(hashbitlen)?;
    if hashval.len() < out_len {
        return Err(BlakeError::Fail);
    }
    let digest = Blake2b512::digest(data);
    hashval[..out_len].copy_from_slice(&digest[..out_len]);
    Ok(())
}
