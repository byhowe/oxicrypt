//! SHA Algorithms
//!
//! # Examples
//!
//! Small example that demonstrates the usage of a SHA function.
//!
//! ```rust
//! # use oxicrypt::digest::*;
//! # use oxicrypt::sha::*;
//! let mut ctx = Sha256::default();
//!
//! ctx.update(b"Hello, ");
//! ctx.update(b"world");
//!
//! let digest = ctx.finish();
//! println!(
//!   "SHA-256 digest of \"Hello, world\" is {}.",
//!   hex::encode(&digest)
//! );
//! ````

use core::mem;
use core::mem::MaybeUninit;
use core::slice;

use oxicrypt_core::sha_generic_sha1_compress;
use oxicrypt_core::sha_generic_sha256_compress;
use oxicrypt_core::sha_generic_sha512_compress;

use crate::digest::DigestInternal;
use crate::digest::DigestMeta;
use crate::digest::Reset;
use crate::digest::Update;
use crate::merkle_damgard;

macro_rules! impl_sha {
  (
    struct $alg_name:ident;
    fn compress = $compress:ident;
    type BitCounter = $counter_int:ident;
    const STATE: [$state_int:ident; $statew:expr] = $initial_state:expr;
    const BLOCK_LEN = $block_len:expr;
    const DIGEST_LEN = $digest_len:expr;
  ) => {
    #[derive(Debug, Clone, Copy)]
    pub struct $alg_name
    {
      h: [$state_int; $statew],
      block: [u8; $block_len],
      index: usize,
      block_count: usize,
    }

    impl $alg_name
    {
      #[inline(always)]
      pub const fn new() -> Self
      {
        let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe { ctx.assume_init_mut() }.reset();
        unsafe { ctx.assume_init() }
      }
    }

    impl DigestMeta for $alg_name
    {
      const BLOCK_LEN: usize = $block_len;
      const DIGEST_LEN: usize = $digest_len;
    }

    impl const Default for $alg_name
    {
      #[inline(always)]
      fn default() -> Self
      {
        Self::new()
      }
    }

    impl const Reset for $alg_name
    {
      #[inline(always)]
      fn reset(&mut self)
      {
        self.h = $initial_state;
        self.index = 0;
        self.block_count = 0;
      }
    }

    impl Update for $alg_name
    {
      fn update(&mut self, data: &[u8])
      {
        let h_ptr = self.h.as_mut_ptr();
        let block_ptr = self.block.as_ptr();
        merkle_damgard::update::<Self, _>(
          data,
          &mut self.block,
          &mut self.index,
          &mut self.block_count,
          || unsafe { $compress(h_ptr, block_ptr) },
        );
      }
    }

    impl DigestInternal for $alg_name
    {
      const LENGTH_COUNTER_W: usize = mem::size_of::<$counter_int>();

      unsafe fn compress(&mut self)
      {
        $compress(self.h.as_mut_ptr(), self.block.as_ptr());
      }

      fn block(&mut self) -> &mut [u8]
      {
        &mut self.block
      }

      fn get_index(&self) -> usize
      {
        self.index
      }

      fn set_index(&mut self, index: usize)
      {
        self.index = index;
      }

      fn increase_block_count(&mut self)
      {
        self.block_count += 1;
      }

      fn get_block_count(&self) -> usize
      {
        self.block_count
      }

      fn write_bits(&mut self, bits: usize)
      {
        self.block[Self::BLOCK_LEN - Self::LENGTH_COUNTER_W ..].copy_from_slice(&$counter_int::to_be_bytes(bits as _));
      }

      fn finish_state(&mut self)
      {
        self.h.iter_mut().for_each(|h0| *h0 = h0.to_be());
      }

      fn state_as_bytes(&self) -> &[u8]
      {
        let data = self.h.as_ptr().cast::<u8>();
        unsafe { slice::from_raw_parts(data, mem::size_of_val(&self.h)) }
      }
    }
  };
}

impl_sha! {
  struct Sha1;
  fn compress = sha_generic_sha1_compress;
  type BitCounter = u64;
  const STATE: [u32; 5] = SHA_INITIAL_H1;
  const BLOCK_LEN = 64;
  const DIGEST_LEN = 20;
}

impl_sha! {
  struct Sha224;
  fn compress = sha_generic_sha256_compress;
  type BitCounter = u64;
  const STATE: [u32; 8] = SHA_INITIAL_H224;
  const BLOCK_LEN = 64;
  const DIGEST_LEN = 28;
}

impl_sha! {
  struct Sha256;
  fn compress = sha_generic_sha256_compress;
  type BitCounter = u64;
  const STATE: [u32; 8] = SHA_INITIAL_H256;
  const BLOCK_LEN = 64;
  const DIGEST_LEN = 32;
}

impl_sha! {
  struct Sha384;
  fn compress = sha_generic_sha512_compress;
  type BitCounter = u128;
  const STATE: [u64; 8] = SHA_INITIAL_H384;
  const BLOCK_LEN = 128;
  const DIGEST_LEN = 48;
}

impl_sha! {
  struct Sha512;
  fn compress = sha_generic_sha512_compress;
  type BitCounter = u128;
  const STATE: [u64; 8] = SHA_INITIAL_H512;
  const BLOCK_LEN = 128;
  const DIGEST_LEN = 64;
}

impl_sha! {
  struct Sha512_224;
  fn compress = sha_generic_sha512_compress;
  type BitCounter = u128;
  const STATE: [u64; 8] = SHA_INITIAL_H512_224;
  const BLOCK_LEN = 128;
  const DIGEST_LEN = 28;
}

impl_sha! {
  struct Sha512_256;
  fn compress = sha_generic_sha512_compress;
  type BitCounter = u128;
  const STATE: [u64; 8] = SHA_INITIAL_H512_256;
  const BLOCK_LEN = 128;
  const DIGEST_LEN = 32;
}

// Initial state for the SHA-1 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H1: [u32; 5] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
  0xc3d2e1f0,
];

/// Initial state for the SHA-224 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H224: [u32; 8] = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];

/// Initial state for the SHA-256 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H256: [u32; 8] = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

/// Initial state for the SHA-384 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H384: [u64; 8] = [
  0xcbbb9d5dc1059ed8,
  0x629a292a367cd507,
  0x9159015a3070dd17,
  0x152fecd8f70e5939,
  0x67332667ffc00b31,
  0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7,
  0x47b5481dbefa4fa4,
];

/// Initial state for the SHA-512 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H512: [u64; 8] = [
  0x6a09e667f3bcc908,
  0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1,
  0x510e527fade682d1,
  0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b,
  0x5be0cd19137e2179,
];

/// Initial state for the SHA-512/224 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H512_224: [u64; 8] = [
  0x8c3d37c819544da2,
  0x73e1996689dcd4d6,
  0x1dfab7ae32ff9c82,
  0x679dd514582f9fcf,
  0x0f6d2b697bd44da8,
  0x77e36f7304c48942,
  0x3f9d85a86a1d36c8,
  0x1112e6ad91d692a1,
];

/// Initial state for the SHA-512/256 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H512_256: [u64; 8] = [
  0x22312194fc2bf72c,
  0x9f555fa3c84c64c2,
  0x2393b86b6f53b151,
  0x963877195940eabd,
  0x96283ee2a88effe3,
  0xbe5e1e2553863992,
  0x2b0199fc2c85b8aa,
  0x0eb72ddc81c52ca2,
];
