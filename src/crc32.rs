#![allow(dead_code)]

//! Defines a wrapper around crc::crc32::Digest, implementing std::hash::Hasher
//! as well as a std::hash::BuildHasher which builds the hasher.
use std::hash::BuildHasher;
use std::hash::Hasher;

/// Wrapper around crc::crc32::Digest which implements std::hash::Hasher
pub struct CRC32Hasher {
    hasher: crc32fast::Hasher,
}

impl CRC32Hasher {
    fn new() -> Self {
        Self {
            hasher: crc32fast::Hasher::new(),
        }
    }
}

impl Hasher for CRC32Hasher {
    fn finish(&self) -> u64 {
        self.hasher.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes)
    }
}

/// std::hash::BuildHasher that builds CRC32Hashers
#[derive(Clone)]
pub struct CRC32BuildHasher;

impl BuildHasher for CRC32BuildHasher {
    type Hasher = CRC32Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        CRC32Hasher::new()
    }
}
