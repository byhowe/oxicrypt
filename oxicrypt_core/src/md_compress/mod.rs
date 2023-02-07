//! Compression functions used by hashing algorithms that use the Merkle–Damgård
//! construction.

mod md5;
mod sha1;
mod sha256;
mod sha512;

pub use md5::md5;
pub use sha1::sha1;
pub use sha256::sha256;
pub use sha512::sha512;
