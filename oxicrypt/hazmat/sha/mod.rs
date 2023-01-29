mod sha1_compress_generic;
mod sha256_compress_generic;
mod sha512_compress_generic;

use core::mem;
use core::mem::MaybeUninit;
use core::slice;

pub mod generic
{
  pub const unsafe fn sha1_compress(state: *mut u32, block: *const u8)
  {
    super::sha1_compress_generic::sha1_compress_generic(state, block);
  }

  pub const unsafe fn sha256_compress(state: *mut u32, block: *const u8)
  {
    super::sha256_compress_generic::sha256_compress_generic(state, block);
  }

  pub const unsafe fn sha512_compress(state: *mut u64, block: *const u8)
  {
    super::sha512_compress_generic::sha512_compress_generic(state, block);
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation
{
  Generic,
}

macro_rules! impl_context {
  (
    struct $context:ident;
    const BLOCK_LEN = $block_len:expr;
    const STATE_LEN = $state_len:expr;
    type STATE_INT = $state_int:ident;
    type LEN_INT = $len_int:ident;
  ) => {
    impl $context
    {
      /// Create a new context with the given state.
      #[inline(always)]
      pub const fn with_state(state: [$state_int; $state_len]) -> Self
      {
        let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe { ctx.assume_init_mut() }.set_state(state);
        unsafe { ctx.assume_init() }
      }

      /// Reset the context using the given state.
      #[inline(always)]
      pub const fn set_state(&mut self, state: [$state_int; $state_len])
      {
        self.h = state;
        self.blocklen = 0;
        self.len = 0;
      }

      /// Consume the context and return the inner state.
      #[inline(always)]
      pub const fn into_state(self) -> [$state_int; $state_len]
      {
        self.h
      }

      /// Return a slice to the inner state.
      #[inline(always)]
      pub fn as_state(&self) -> &[u8]
      {
        unsafe { slice::from_raw_parts(self.h.as_ptr().cast::<u8>(), $state_len * mem::size_of::<$state_int>()) }
      }

      /// Update the state with the given data.
      #[inline(always)]
      pub fn update<const I: Implementation>(&mut self, mut data: &[u8])
      {
        // Loop until all the data is read.
        while !data.is_empty() {
          let emptyspace = $block_len - self.blocklen;
          // If there is enough empty space in the inner block, then we can just copy `data` into
          // `self.block`.
          if emptyspace >= data.len() {
            let newblocklen = self.blocklen + data.len();
            self.block[self.blocklen .. newblocklen].copy_from_slice(data);
            self.blocklen = newblocklen;
            // We need to set the length of `data` to 0 so we can exit out of the loop.
            data = &data[0 .. 0];
          } else {
            self.block[self.blocklen .. $block_len].copy_from_slice(&data[0 .. emptyspace]);
            // We filled `self.block` completely.
            self.blocklen = $block_len;
            data = &data[emptyspace ..];
          }

          if self.blocklen == $block_len {
            // SAFETY: We know the inner block is full.
            unsafe { self.compress::<I>() };
            self.blocklen = 0;
            self.len += $block_len;
          }
        }
      }

      /// Calculates the digest value and store the result in the inner state.
      ///
      /// The calculated result can be accessed via [`as_state`](`Self::as_state`).
      #[inline(always)]
      pub fn finish<const I: Implementation>(&mut self)
      {
        // We can do this without checking for `self.blocklen`, because we know `update` makes sure
        // `self.blocklen` is always less than block length.
        self.block[self.blocklen] = 0b10000000;
        // Increment the inner length counter to account for the latest block length.
        self.len += self.blocklen as $len_int;
        // Account for the byte we added.
        self.blocklen += 1;

        // If there is not enough space to write the inner length counter, fill the remaining space with
        // zeros and compress the block.
        if self.blocklen > ($block_len - mem::size_of::<$len_int>()) {
          self.block[self.blocklen ..].fill(0);
          unsafe { self.compress::<I>() };
          self.blocklen = 0;
        }

        self.block[self.blocklen .. $block_len - mem::size_of::<$len_int>()].fill(0);
        self.len *= 8;
        self.block[$block_len - mem::size_of::<$len_int>() ..].copy_from_slice(&self.len.to_be_bytes());
        unsafe { self.compress::<I>() };

        for i in 0 .. $state_len {
          self.h[i] = self.h[i].to_be();
        }
      }
    }
  };
}

/// Unsafe SHA-1 context.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Context1
{
  h: [u32; 5],
  block: [u8; 64],
  blocklen: usize,
  len: u64,
}

impl Context1
{
  #[allow(clippy::missing_safety_doc)]
  #[allow(unused_variables)]
  unsafe fn compress<const I: Implementation>(&mut self)
  {
    match I {
      | Implementation::Generic => generic::sha1_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
    }
  }
}

/// Unsafe SHA-256 context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Context256
{
  h: [u32; 8],
  block: [u8; 64],
  blocklen: usize,
  len: u64,
}

impl Context256
{
  #[allow(clippy::missing_safety_doc)]
  #[allow(unused_variables)]
  unsafe fn compress<const I: Implementation>(&mut self)
  {
    match I {
      | Implementation::Generic => generic::sha256_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
    }
  }
}

/// Unsafe SHA-512 context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Context512
{
  h: [u64; 8],
  block: [u8; 128],
  blocklen: usize,
  len: u128,
}

impl Context512
{
  #[allow(clippy::missing_safety_doc)]
  #[allow(unused_variables)]
  unsafe fn compress<const I: Implementation>(&mut self)
  {
    match I {
      | Implementation::Generic => generic::sha512_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
    }
  }
}

impl_context! {
  struct Context1;
  const BLOCK_LEN = 64;
  const STATE_LEN = 5;
  type STATE_INT = u32;
  type LEN_INT = u64;
}

impl_context! {
  struct Context256;
  const BLOCK_LEN = 64;
  const STATE_LEN = 8;
  type STATE_INT = u32;
  type LEN_INT = u64;
}

impl_context! {
  struct Context512;
  const BLOCK_LEN = 128;
  const STATE_LEN = 8;
  type STATE_INT = u64;
  type LEN_INT = u128;
}

/// Initial state for the SHA-1 algorithm.
#[rustfmt::skip]
pub const H1: [u32; 5] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
  0xc3d2e1f0,
];

/// Initial state for the SHA-224 algorithm.
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

/// Initial state for the SHA-256 algorithm.
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

/// Initial state for the SHA-384 algorithm.
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

/// Initial state for the SHA-512 algorithm.
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

/// Initial state for the SHA-512/224 algorithm.
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

/// Initial state for the SHA-512/256 algorithm.
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
