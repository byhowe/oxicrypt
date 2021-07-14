//! HMAC.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::mem::MaybeUninit;

use crate::sha;

/// Hash functions that can be used with HMAC.
pub trait Digest
{
  type Implementation: Copy;

  fn digest_reset(&mut self);

  fn digest_update<D: AsRef<[u8]>>(&mut self, implementation: Self::Implementation, data: D);

  fn digest_finish(&mut self, implementation: Self::Implementation, output: &mut [u8]);
}

/// HMAC context.
///
/// # Safety
///
/// It is undefined behaviour to specify `(H, O, B)` generics other than:
///
/// * HMAC-SHA-1 - `(Sha1, 20, 64)`
/// * HMAC-SHA-224 - `(Sha224, 28, 64)`
/// * HMAC-SHA-256 - `(Sha256, 32, 64)`
/// * HMAC-SHA-384 - `(Sha384, 48, 128)`
/// * HMAC-SHA-512 - `(Sha512, 64, 128)`
/// * HMAC-SHA-512/224 - `(Sha512_224, 28, 128)`
/// * HMAC-SHA-512/256 - `(Sha512_256, 32, 128)`
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Hmac<H, const O: usize, const B: usize>
where
  H: Digest,
{
  hash: H,
  key: [u8; B],
}

/// HMAC-SHA-1
pub type HmacSha1 = Hmac<sha::Sha1, 20, 64>;
/// HMAC-SHA-224
pub type HmacSha224 = Hmac<sha::Sha224, 28, 64>;
/// HMAC-SHA-256
pub type HmacSha256 = Hmac<sha::Sha256, 32, 64>;
/// HMAC-SHA-384
pub type HmacSha384 = Hmac<sha::Sha384, 48, 128>;
/// HMAC-SHA-512
pub type HmacSha512 = Hmac<sha::Sha512, 64, 128>;
/// HMAC-SHA-512/224
pub type HmacSha512_224 = Hmac<sha::Sha512_224, 28, 128>;
/// HMAC-SHA-512/256
pub type HmacSha512_256 = Hmac<sha::Sha512_256, 32, 128>;

impl<H, const O: usize, const B: usize> Hmac<H, O, B>
where
  H: Digest,
{
  pub fn with_key<K: AsRef<[u8]>>(implementation: H::Implementation, key: K) -> Self
  {
    let mut ctx = Self {
      hash: unsafe { MaybeUninit::uninit().assume_init() },
      key: [0; B],
    };
    ctx.set_key(implementation, key);
    ctx
  }

  pub fn set_key<K: AsRef<[u8]>>(&mut self, implementation: H::Implementation, key: K)
  {
    let key = key.as_ref();
    self.hash.digest_reset();
    if key.len() > B {
      self.hash.digest_update(implementation, key);
      self.hash.digest_finish(implementation, &mut self.key);
      self.hash.digest_reset();
    } else {
      self.key[0 .. key.len()].copy_from_slice(key);
    }
    for i in 0 .. B {
      self.key[i] ^= 0x36;
    }
    self.hash.digest_update(implementation, &self.key);
  }

  pub fn update<D: AsRef<[u8]>>(&mut self, implementation: H::Implementation, data: D)
  {
    self.hash.digest_update(implementation, data);
  }

  pub fn finish(&mut self, implementation: H::Implementation) -> [u8; O]
  {
    let mut output: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    self.finish_into(implementation, unsafe { output.assume_init_mut() });
    unsafe { output.assume_init() }
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn finish_boxed(&mut self, implementation: H::Implementation) -> Box<[u8]>
  {
    let mut output = unsafe { Box::new_uninit_slice(O).assume_init() };
    self.finish_into(implementation, &mut output);
    output
  }

  pub fn finish_into(&mut self, implementation: H::Implementation, output: &mut [u8])
  {
    let mut digest: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    self
      .hash
      .digest_finish(implementation, unsafe { digest.assume_init_mut() });
    self.hash.digest_reset();
    for i in 0 .. B {
      self.key[i] ^= 0x36;
      self.key[i] ^= 0x5c;
    }
    self.hash.digest_update(implementation, &self.key);
    self
      .hash
      .digest_update(implementation, unsafe { digest.assume_init_ref() });
    self.hash.digest_finish(implementation, output);
  }

  pub fn oneshot<K: AsRef<[u8]>, D: AsRef<[u8]>>(implementation: H::Implementation, key: K, data: D) -> [u8; O]
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish(implementation)
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn oneshot_boxed<K: AsRef<[u8]>, D: AsRef<[u8]>>(implementation: H::Implementation, key: K, data: D)
  -> Box<[u8]>
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish_boxed(implementation)
  }

  pub fn oneshot_into<K: AsRef<[u8]>, D: AsRef<[u8]>>(
    implementation: H::Implementation,
    data: D,
    key: K,
    output: &mut [u8],
  )
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish_into(implementation, output);
  }
}
