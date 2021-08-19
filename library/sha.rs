//! High level SHA API.
//!
//! # Examples
//!
//! Small example that demonstrates the usage of a SHA function.
//!
//! ```
//! use oxicrypt::sha::Sha256;
//!
//! let mut ctx = Sha256::new();
//!
//! ctx.update(b"Hello, ");
//! ctx.update(b"world");
//!
//! let digest = ctx.finish_sliced();
//! println!("SHA-256 digest of \"Hello, world\" is {}.", hex::encode(digest));
//! ```

use core::mem::MaybeUninit;

use crate::hazmat::sha::Engine1;
use crate::hazmat::sha::Engine256;
use crate::hazmat::sha::Engine512;
use crate::hazmat::sha::H1;
use crate::hazmat::sha::H224;
use crate::hazmat::sha::H256;
use crate::hazmat::sha::H384;
use crate::hazmat::sha::H512;
use crate::hazmat::sha::H512_224;
use crate::hazmat::sha::H512_256;
use crate::Control;
use crate::Implementation;

macro_rules! impl_sha {
  (
    struct $sha:ident;
    const DIGEST_LEN = $digest_len:expr;
    const BLOCK_LEN = $block_len:expr;
    const STATE = $state:expr;
    type Engine = $engine:ident;
  ) => {
    impl Default for $sha
    {
      fn default() -> Self
      {
        Self::new()
      }
    }

    impl core::hash::Hasher for $sha
    {
      fn finish(&self) -> u64
      {
        let mut ctx: Self = *self;
        let mut digest: MaybeUninit<[u8; 8]> = MaybeUninit::uninit();
        unsafe { digest.assume_init_mut() }.copy_from_slice(&ctx.finish_sliced()[0 .. 8]);
        u64::from_be_bytes(unsafe { digest.assume_init() })
      }

      fn write(&mut self, bytes: &[u8])
      {
        self.update(bytes);
      }
    }

    #[cfg(any(feature = "std", doc))]
    #[doc(cfg(feature = "std"))]
    impl std::io::Write for $sha
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

    impl $sha
    {
      /// Block length used by the algorithm.
      pub const BLOCK_LEN: usize = $block_len;
      /// Digest length used by the algorithm.
      pub const DIGEST_LEN: usize = $digest_len;

      /// Creates a new SHA context.
      pub const fn new() -> Self
      {
        Self {
          engine: $engine::with_state($state),
        }
      }

      /// Resets the context to its original state.
      pub const fn reset(&mut self)
      {
        self.engine.set_state($state);
      }

      /// Updates the context with the given data.
      pub fn update(&mut self, data: &[u8])
      {
        self.engine.update(Control::get_global_implementation(), data);
      }

      /// Same as [`update`](`Self::update`), but accepts an `Implementation` variable.
      pub fn update_impl(&mut self, implementation: Implementation, data: &[u8])
      {
        self.engine.update(implementation, data);
      }

      /// Calculate the digest and return a reference to it.
      ///
      /// The returned reference is only valid until the context is mutated.
      pub fn finish_sliced<'context>(&'context mut self) -> &'context [u8]
      {
        self.finish_sliced_impl(Control::get_global_implementation())
      }

      /// Same as [`finish_sliced`](`Self::finish_sliced`), but accepts an `Implementation` variable.
      pub fn finish_sliced_impl<'context>(&'context mut self, implementation: Implementation) -> &'context [u8]
      {
        self.engine.finish(implementation);
        &self.engine.as_state()[0 .. $digest_len]
      }

      /// Calculates the digest and returns it.
      pub fn finish(&mut self) -> [u8; $digest_len]
      {
        self.finish_impl(Control::get_global_implementation())
      }

      /// Same as [`finish`](`Self::finish`), but accepts an `Implementation` variable.
      pub fn finish_impl(&mut self, implementation: Implementation) -> [u8; $digest_len]
      {
        let mut digest: MaybeUninit<[u8; $digest_len]> = MaybeUninit::uninit();
        self.engine.finish(implementation);
        unsafe { digest.assume_init_mut() }.copy_from_slice(&self.engine.as_state()[0 .. $digest_len]);
        unsafe { digest.assume_init() }
      }

      /// Calculates the digest and writes into the given buffer.
      ///
      /// The length of the provided buffer does not matter.
      pub fn finish_into(&mut self, output: &mut [u8])
      {
        self.finish_into_impl(Control::get_global_implementation(), output);
      }

      /// Same as [`finish_into`](`Self::finish_into`), but accepts an `Implementation` variable.
      pub fn finish_into_impl(&mut self, implementation: Implementation, output: &mut [u8])
      {
        let n = core::cmp::min($digest_len, output.len());
        let digest = self.finish_sliced_impl(implementation);
        output[0 .. n].copy_from_slice(&digest[0 .. n]);
      }

      /// Compute the hash of a given data in one go.
      pub fn oneshot(data: &[u8]) -> [u8; $digest_len]
      {
        Self::oneshot_impl(Control::get_global_implementation(), data)
      }

      /// Same as [`oneshot`](`Self::oneshot`), but accepts an `Implementation` variable.
      pub fn oneshot_impl(implementation: Implementation, data: &[u8]) -> [u8; $digest_len]
      {
        let mut ctx = Self::new();
        ctx.update_impl(implementation, data);
        ctx.finish_impl(implementation)
      }

      /// Compute the hash of a given data in one go and writes the result into the given output buffer.
      pub fn oneshot_into(data: &[u8], output: &mut [u8])
      {
        Self::oneshot_into_impl(Control::get_global_implementation(), data, output);
      }

      /// Same as [`oneshot_into`](`Self::oneshot_into`), but accepts an `Implementation` variable.
      pub fn oneshot_into_impl(implementation: Implementation, data: &[u8], output: &mut [u8])
      {
        let mut ctx = Self::new();
        ctx.update_impl(implementation, data);
        ctx.finish_into_impl(implementation, output);
      }
    }
  };
}

/// SHA-1 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha1
{
  engine: Engine1,
}

/// SHA-224 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha224
{
  engine: Engine256,
}

/// SHA-256 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha256
{
  engine: Engine256,
}

/// SHA-384 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha384
{
  engine: Engine512,
}

/// SHA-512 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha512
{
  engine: Engine512,
}

/// SHA-512/224 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha512_224
{
  engine: Engine512,
}

/// SHA-512/256 context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Sha512_256
{
  engine: Engine512,
}

impl_sha! {
  struct Sha1;
  const DIGEST_LEN = 20;
  const BLOCK_LEN = 64;
  const STATE = H1;
  type Engine = Engine1;
}

impl_sha! {
  struct Sha224;
  const DIGEST_LEN = 28;
  const BLOCK_LEN = 64;
  const STATE = H224;
  type Engine = Engine256;
}

impl_sha! {
  struct Sha256;
  const DIGEST_LEN = 32;
  const BLOCK_LEN = 64;
  const STATE = H256;
  type Engine = Engine256;
}

impl_sha! {
  struct Sha384;
  const DIGEST_LEN = 48;
  const BLOCK_LEN = 128;
  const STATE = H384;
  type Engine = Engine512;
}

impl_sha! {
  struct Sha512;
  const DIGEST_LEN = 64;
  const BLOCK_LEN = 128;
  const STATE = H512;
  type Engine = Engine512;
}

impl_sha! {
  struct Sha512_224;
  const DIGEST_LEN = 28;
  const BLOCK_LEN = 128;
  const STATE = H512_224;
  type Engine = Engine512;
}

impl_sha! {
  struct Sha512_256;
  const DIGEST_LEN = 32;
  const BLOCK_LEN = 128;
  const STATE = H512_256;
  type Engine = Engine512;
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::cavp::*;

  macro_rules! add_test {
    ($fn:ident, $sha:ident, $tests:expr) => {
      #[test]
      fn $fn()
      {
        let mut ctx = $sha::new();
        for (md, msg, _) in $tests {
          let mdb = hex::decode(md).unwrap();
          let msgb = hex::decode(msg).unwrap();

          ctx.update(&msgb);
          let digest = ctx.finish();
          assert_eq!(mdb, digest);
          ctx.reset();

          ctx.update(&msgb);
          let digest = ctx.finish_sliced();
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
