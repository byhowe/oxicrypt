//! HMAC.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::mem::MaybeUninit;

use crate::digest::Digest;
use crate::sha;
use crate::Implementation;

/// HMAC context.
///
/// # Safety
///
/// It is undefined behaviour to specify `(D, M, O, B)` generics other than:
///
/// * HMAC-SHA-1 - `(Sha1, 0x5ba_1, 20, 64)`
/// * HMAC-SHA-224 - `(Sha224, 0x5ba_224, 28, 64)`
/// * HMAC-SHA-256 - `(Sha256, 0x5ba_256, 32, 64)`
/// * HMAC-SHA-384 - `(Sha384, 0x5ba_384, 48, 128)`
/// * HMAC-SHA-512 - `(Sha512, 0x5ba_512, 64, 128)`
/// * HMAC-SHA-512/224 - `(Sha512_224, 0x5ba_512_224, 28, 128)`
/// * HMAC-SHA-512/256 - `(Sha512_256, 0x5ba_512_256, 32, 128)`
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Hmac<D, const M: usize, const O: usize, const B: usize>
{
  hash: Digest<D, M, O>,
  x5c: bool,
  key: [u8; B],
}

/// HMAC-SHA-1
pub type HmacSha1 = Hmac<sha::Sha1, 0x5ba_1, 20, 64>;
/// HMAC-SHA-224
pub type HmacSha224 = Hmac<sha::Sha224, 0x5ba_224, 28, 64>;
/// HMAC-SHA-256
pub type HmacSha256 = Hmac<sha::Sha256, 0x5ba_256, 32, 64>;
/// HMAC-SHA-384
pub type HmacSha384 = Hmac<sha::Sha384, 0x5ba_384, 48, 128>;
/// HMAC-SHA-512
pub type HmacSha512 = Hmac<sha::Sha512, 0x5ba_512, 64, 128>;
/// HMAC-SHA-512/224
pub type HmacSha512_224 = Hmac<sha::Sha512_224, 0x5ba_512_224, 28, 128>;
/// HMAC-SHA-512/256
pub type HmacSha512_256 = Hmac<sha::Sha512_256, 0x5ba_512_256, 32, 128>;

impl<D, const M: usize, const O: usize, const B: usize> Hmac<D, M, O, B>
{
  pub fn with_key<K: AsRef<[u8]>>(implementation: Implementation, key: K) -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.set_key(implementation, key);
    unsafe { ctx.assume_init() }
  }

  pub fn set_key<K: AsRef<[u8]>>(&mut self, implementation: Implementation, key: K)
  {
    let key = key.as_ref();
    self.hash.reset();
    self.key = [0; B];
    if key.len() > B {
      self.hash.update(implementation, key);
      self.hash.finish_into(implementation, &mut self.key);
      self.hash.reset();
    } else {
      self.key[0 .. key.len()].copy_from_slice(key);
    }
    for i in 0 .. B {
      self.key[i] ^= 0x36;
    }
    self.x5c = false;
    self.hash.update(implementation, &self.key);
  }

  pub fn reset(&mut self, implementation: Implementation)
  {
    if self.x5c {
      for i in 0 .. B {
        self.key[i] ^= 0x36 ^ 0x5c;
      }
      self.x5c = false;
    }
    self.hash.reset();
    self.hash.update(implementation, &self.key);
  }

  pub fn update<I: AsRef<[u8]>>(&mut self, implementation: Implementation, data: I)
  {
    self.hash.update(implementation, data.as_ref());
  }

  pub fn finish(&mut self, implementation: Implementation) -> [u8; O]
  {
    let mut output: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    self.finish_into(implementation, unsafe { output.assume_init_mut() });
    unsafe { output.assume_init() }
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn finish_boxed(&mut self, implementation: Implementation) -> Box<[u8]>
  {
    let mut output = unsafe { Box::new_uninit_slice(O).assume_init() };
    self.finish_into(implementation, &mut output);
    output
  }

  fn finish_raw(&mut self, implementation: Implementation)
  {
    let mut digest: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    self
      .hash
      .finish_into(implementation, unsafe { digest.assume_init_mut() });
    self.hash.reset();
    for i in 0 .. B {
      self.key[i] ^= 0x36 ^ 0x5c;
    }
    self.x5c = true;
    self.hash.update(implementation, &self.key);
    self.hash.update(implementation, unsafe { digest.assume_init_ref() });
  }

  pub fn finish_into(&mut self, implementation: Implementation, output: &mut [u8])
  {
    self.finish_raw(implementation);
    self.hash.finish_into(implementation, output);
  }

  pub fn finish_sliced(&mut self, implementation: Implementation) -> &[u8]
  {
    self.finish_raw(implementation);
    self.hash.finish_sliced(implementation)
  }

  pub fn oneshot<K: AsRef<[u8]>, I: AsRef<[u8]>>(implementation: Implementation, key: K, data: I) -> [u8; O]
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish(implementation)
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn oneshot_boxed<K: AsRef<[u8]>, I: AsRef<[u8]>>(implementation: Implementation, key: K, data: I) -> Box<[u8]>
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish_boxed(implementation)
  }

  pub fn oneshot_into<K: AsRef<[u8]>, I: AsRef<[u8]>>(
    implementation: Implementation,
    data: I,
    key: K,
    output: &mut [u8],
  )
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish_into(implementation, output);
  }
}
