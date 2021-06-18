mod sha1_compress_generic;
mod sha256_compress_generic;
mod sha512_compress_generic;

pub mod generic
{
  pub use super::sha1_compress_generic::sha1_compress_generic;
  pub use super::sha256_compress_generic::sha256_compress_generic;
  pub use super::sha512_compress_generic::sha512_compress_generic;
}

/// Initial state of the SHA-1 algorithm.
#[rustfmt::skip]
pub const H1: [u32; 5] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
  0xc3d2e1f0,
];

/// Initial state of the SHA-224 algorithm.
#[rustfmt::skip]
pub const H224: [u32; 8] = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];

/// Initial state of the SHA-256 algorithm.
#[rustfmt::skip]
pub const H256: [u32; 8] = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

/// Initial state of the SHA-384 algorithm.
#[rustfmt::skip]
pub const H384: [u64; 8] = [
  0xcbbb9d5dc1059ed8,
  0x629a292a367cd507,
  0x9159015a3070dd17,
  0x152fecd8f70e5939,
  0x67332667ffc00b31,
  0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7,
  0x47b5481dbefa4fa4,
];

/// Initial state of the SHA-512 algorithm.
#[rustfmt::skip]
pub const H512: [u64; 8] = [
  0x6a09e667f3bcc908,
  0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1,
  0x510e527fade682d1,
  0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b,
  0x5be0cd19137e2179,
];

/// Initial state of the SHA-512/224 algorithm.
#[rustfmt::skip]
pub const H512_224: [u64; 8] = [
  0x8c3d37c819544da2,
  0x73e1996689dcd4d6,
  0x1dfab7ae32ff9c82,
  0x679dd514582f9fcf,
  0x0f6d2b697bd44da8,
  0x77e36f7304c48942,
  0x3f9d85a86a1d36c8,
  0x1112e6ad91d692a1,
];

/// Initial state of the SHA-512/256 algorithm.
#[rustfmt::skip]
pub const H512_256: [u64; 8] = [
  0x22312194fc2bf72c,
  0x9f555fa3c84c64c2,
  0x2393b86b6f53b151,
  0x963877195940eabd,
  0x96283ee2a88effe3,
  0xbe5e1e2553863992,
  0x2b0199fc2c85b8aa,
  0x0eb72ddc81c52ca2,
];
