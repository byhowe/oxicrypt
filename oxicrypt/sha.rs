//! High level SHA API.
//!
//! # Examples
//!
//! Small example that demonstrates the usage of a SHA function.
//!
//! ```
//! use oxicrypt::digest::Finish;
//! use oxicrypt::digest::Update;
//! use oxicrypt::sha::Implementation;
//! use oxicrypt::sha::Sha256;
//!
//! let mut ctx = Sha256::<{ Implementation::Generic }>::default();
//!
//! ctx.update(b"Hello, ");
//! ctx.update(b"world");
//!
//! let digest = ctx.finish();
//! println!("SHA-256 digest of \"Hello, world\" is {}.", hex::encode(&digest));
//! ```

use core::mem::MaybeUninit;

use crate::digest::DigestMeta;
use crate::digest::FinishInternal;
use crate::digest::FinishToSlice;
use crate::digest::Reset;
use crate::digest::Sha;
use crate::digest::Update;
use crate::hazmat::sha::Context1;
use crate::hazmat::sha::Context256;
use crate::hazmat::sha::Context512;
#[doc(inline)]
pub use crate::hazmat::sha::Implementation;
use crate::hazmat::sha::H1;
use crate::hazmat::sha::H224;
use crate::hazmat::sha::H256;
use crate::hazmat::sha::H384;
use crate::hazmat::sha::H512;
use crate::hazmat::sha::H512_224;
use crate::hazmat::sha::H512_256;

use core::mem;
use core::slice;

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

macro_rules! impl_sha {
  (
    struct $sha:ident;
    const DIGEST_LEN = $digest_len:expr;
    const BLOCK_LEN = $block_len:expr;
    const STATE = $state:expr;
    type Context = $ctx:ident;
  ) => {
    impl<const I: Implementation> DigestMeta for $sha<I>
    {
      const BLOCK_LEN: usize = $block_len;
      const DIGEST_LEN: usize = $digest_len;
    }

    impl<const I: Implementation> Sha for $sha<I> {}

    impl<const I: Implementation> const Default for $sha<I>
    {
      fn default() -> Self
      {
        let mut ctx: MaybeUninit<$sha<I>> = MaybeUninit::uninit();
        unsafe { ctx.assume_init_mut() }.reset();
        unsafe { ctx.assume_init() }
      }
    }

    impl<const I: Implementation> core::hash::Hasher for $sha<I>
    {
      fn finish(&self) -> u64
      {
        let mut ctx: Self = *self;
        let mut digest: MaybeUninit<[u8; 8]> = MaybeUninit::uninit();
        ctx.finish_to_slice(unsafe { digest.assume_init_mut() });
        u64::from_be_bytes(unsafe { digest.assume_init() })
      }

      fn write(&mut self, bytes: &[u8])
      {
        self.update(bytes);
      }
    }

    #[cfg(any(feature = "std", doc))]
    #[doc(cfg(feature = "std"))]
    impl<const I: Implementation> std::io::Write for $sha<I>
    {
      fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>
      {
        self.update(buf);
        Ok(buf.len())
      }

      fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>
      {
        self.update(buf);
        Ok(())
      }

      fn flush(&mut self) -> std::io::Result<()>
      {
        Ok(())
      }
    }

    impl<const I: Implementation> const Reset for $sha<I>
    {
      fn reset(&mut self)
      {
        self.ctx.set_state($state);
      }
    }

    impl<const I: Implementation> Update for $sha<I>
    {
      fn update(&mut self, data: &[u8])
      {
        self.ctx.update::<I>(data);
      }
    }

    impl<const I: Implementation> FinishInternal for $sha<I>
    {
      fn finish_internal(&mut self) -> &[u8]
      {
        self.ctx.finish::<I>();
        &self.ctx.as_state()[0 .. $digest_len]
      }
    }
  };
}

/// SHA-1 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha1<const I: Implementation>
{
  ctx: Context1,
}

/// SHA-224 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha224<const I: Implementation>
{
  ctx: Context256,
}

/// SHA-256 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha256<const I: Implementation>
{
  ctx: Context256,
}

/// SHA-384 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha384<const I: Implementation>
{
  ctx: Context512,
}

/// SHA-512 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha512<const I: Implementation>
{
  ctx: Context512,
}

/// SHA-512/224 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha512_224<const I: Implementation>
{
  ctx: Context512,
}

/// SHA-512/256 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha512_256<const I: Implementation>
{
  ctx: Context512,
}

impl_sha! {
  struct Sha1;
  const DIGEST_LEN = 20;
  const BLOCK_LEN = 64;
  const STATE = H1;
  type Context = Context1;
}

impl_sha! {
  struct Sha224;
  const DIGEST_LEN = 28;
  const BLOCK_LEN = 64;
  const STATE = H224;
  type Context = Context256;
}

impl_sha! {
  struct Sha256;
  const DIGEST_LEN = 32;
  const BLOCK_LEN = 64;
  const STATE = H256;
  type Context = Context256;
}

impl_sha! {
  struct Sha384;
  const DIGEST_LEN = 48;
  const BLOCK_LEN = 128;
  const STATE = H384;
  type Context = Context512;
}

impl_sha! {
  struct Sha512;
  const DIGEST_LEN = 64;
  const BLOCK_LEN = 128;
  const STATE = H512;
  type Context = Context512;
}

impl_sha! {
  struct Sha512_224;
  const DIGEST_LEN = 28;
  const BLOCK_LEN = 128;
  const STATE = H512_224;
  type Context = Context512;
}

impl_sha! {
  struct Sha512_256;
  const DIGEST_LEN = 32;
  const BLOCK_LEN = 128;
  const STATE = H512_256;
  type Context = Context512;
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::digest::Finish;
  use crate::test_vectors::cavp::*;

  macro_rules! add_test {
    ($fn:ident, $sha:ident, $tests:expr) => {
      #[test]
      fn $fn()
      {
        let mut ctx = $sha::<{ Implementation::Generic }>::default();
        for (md, msg, _) in $tests {
          let mdb = hex::decode(md).unwrap();
          let msgb = hex::decode(msg).unwrap();

          ctx.update(&msgb);
          let digest = ctx.finish();
          assert_eq!(mdb, digest);
          ctx.reset();
        }
      }
    };
  }

  add_test!(sha1, Sha1, SHA1);
  add_test!(sha224, Sha224, SHA224);
  add_test!(sha256, Sha256, SHA256);
  add_test!(sha384, Sha384, SHA384);
  add_test!(sha512, Sha512, SHA512);
  add_test!(sha512_224, Sha512_224, SHA512_224);
  add_test!(sha512_256, Sha512_256, SHA512_256);
}
