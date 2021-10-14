//! High level SHA API.
//!
//! # Examples
//!
//! Small example that demonstrates the usage of a SHA function.
//!
//! ```
//! use oxicrypt::digest::Digest;
//! use oxicrypt::sha::Implementation;
//! use oxicrypt::sha::Sha256;
//!
//! let mut ctx = Sha256::<{ Implementation::Generic }>::new();
//!
//! ctx.update(b"Hello, ");
//! ctx.update(b"world");
//!
//! let digest = ctx.finish();
//! println!("SHA-256 digest of \"Hello, world\" is {}.", hex::encode(&digest));
//! ```

use core::cmp;
use core::mem::MaybeUninit;

use crate::digest::Digest;
use crate::digest::DigestInformation;
use crate::digest::Finish;
use crate::digest::Reset;
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
use crate::marker::Sha;

macro_rules! impl_sha {
  (
    struct $sha:ident;
    const DIGEST_LEN = $digest_len:expr;
    const BLOCK_LEN = $block_len:expr;
    const STATE = $state:expr;
    type Context = $ctx:ident;
  ) => {
    impl<const I: Implementation> Sha for $sha<I> {}

    impl<const I: Implementation> const Default for $sha<I>
    {
      fn default() -> Self
      {
        Self::new()
      }
    }

    impl<const I: Implementation> core::hash::Hasher for $sha<I>
    {
      fn finish(&self) -> u64
      {
        let mut ctx: Self = *self;
        let mut digest: MaybeUninit<[u8; 8]> = MaybeUninit::uninit();
        ctx.finish_into(unsafe { digest.assume_init_mut() });
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

    impl<const I: Implementation> DigestInformation for $sha<I>
    {
      const BLOCK_LEN: usize = $block_len;
      const DIGEST_LEN: usize = $digest_len;
    }

    impl<const I: Implementation> const Reset for $sha<I>
    {
      fn new() -> Self
      {
        let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe { ctx.assume_init_mut() }.reset();
        unsafe { ctx.assume_init() }
      }

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

    impl<const I: Implementation> Finish for $sha<I>
    {
      fn finish_into(&mut self, buf: &mut [u8])
      {
        self.ctx.finish::<I>();
        let n = cmp::min($digest_len, buf.len());
        let digest = &self.ctx.as_state()[0 .. $digest_len];
        buf[0 .. n].copy_from_slice(&digest[0 .. n]);
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
  use crate::test_vectors::cavp::*;

  macro_rules! add_test {
    ($fn:ident, $sha:ident, $tests:expr) => {
      #[test]
      fn $fn()
      {
        let mut ctx = $sha::<{ Implementation::Generic }>::new();
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
