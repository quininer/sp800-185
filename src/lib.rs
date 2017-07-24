//! SHA-3 Derived Functions (SP800-185) Implementation in Rust.


extern crate byteorder;
extern crate tiny_keccak;
#[cfg(feature = "parallelhash")] extern crate rayon;

pub mod utils;
mod cshake;
mod kmac;
mod tuplehash;

pub use cshake::CShake;
pub use kmac::KMac;
pub use tuplehash::TupleHash;

#[cfg(feature = "parallelhash")] mod parallelhash;
#[cfg(feature = "parallelhash")] pub use parallelhash::ParallelHash;
