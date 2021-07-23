//! HMAC.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::mem::MaybeUninit;

use crate::sha;
use crate::Implementation;

enum Variant
{
  Sha(crate::hazmat::sha::Variant),
}

/// HMAC context.
///
/// # Safety
///
/// It is undefined behaviour to specify `(H, M, O, B)` generics other than:
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
pub struct Hmac<H, const M: usize, const O: usize, const B: usize>
{
  hash: H,
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

impl<H, const M: usize, const O: usize, const B: usize> Hmac<H, M, O, B>
{
  const V: Variant = {
    use crate::hazmat::sha::Variant::*;
    match (M, O, B) {
      | (0x5ba_1, 20, 64) => Variant::Sha(Sha1),
      | (0x5ba_224, 28, 64) => Variant::Sha(Sha224),
      | (0x5ba_256, 32, 64) => Variant::Sha(Sha256),
      | (0x5ba_384, 48, 128) => Variant::Sha(Sha384),
      | (0x5ba_512, 64, 128) => Variant::Sha(Sha512),
      | (0x5ba_512_224, 28, 128) => Variant::Sha(Sha512_224),
      | (0x5ba_512_256, 32, 128) => Variant::Sha(Sha512_256),
      | _ => unsafe { core::hint::unreachable_unchecked() },
    }
  };

  const fn digest_reset(hash: &mut H)
  {
    use core::mem::transmute;

    use crate::hazmat::sha::Variant::*;
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha(Sha1) => unsafe { transmute::<&mut H, &mut sha::Sha1>(hash) }.reset(),
      | Variant::Sha(Sha224) => unsafe { transmute::<&mut H, &mut sha::Sha224>(hash) }.reset(),
      | Variant::Sha(Sha256) => unsafe { transmute::<&mut H, &mut sha::Sha256>(hash) }.reset(),
      | Variant::Sha(Sha384) => unsafe { transmute::<&mut H, &mut sha::Sha384>(hash) }.reset(),
      | Variant::Sha(Sha512) => unsafe { transmute::<&mut H, &mut sha::Sha512>(hash) }.reset(),
      | Variant::Sha(Sha512_224) => unsafe { transmute::<&mut H, &mut sha::Sha512_224>(hash) }.reset(),
      | Variant::Sha(Sha512_256) => unsafe { transmute::<&mut H, &mut sha::Sha512_256>(hash) }.reset(),
    }
  }

  fn digest_update(hash: &mut H, implementation: Implementation, data: &[u8])
  {
    use core::mem::transmute;

    use crate::hazmat::sha::Variant::*;
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha(Sha1) => unsafe { transmute::<&mut H, &mut sha::Sha1>(hash) }.update(implementation, data),
      | Variant::Sha(Sha224) => unsafe { transmute::<&mut H, &mut sha::Sha224>(hash) }.update(implementation, data),
      | Variant::Sha(Sha256) => unsafe { transmute::<&mut H, &mut sha::Sha256>(hash) }.update(implementation, data),
      | Variant::Sha(Sha384) => unsafe { transmute::<&mut H, &mut sha::Sha384>(hash) }.update(implementation, data),
      | Variant::Sha(Sha512) => unsafe { transmute::<&mut H, &mut sha::Sha512>(hash) }.update(implementation, data),
      | Variant::Sha(Sha512_224) => unsafe { transmute::<&mut H, &mut sha::Sha512_224>(hash) }.update(implementation, data),
      | Variant::Sha(Sha512_256) => unsafe { transmute::<&mut H, &mut sha::Sha512_256>(hash) }.update(implementation, data),
    }
  }

  fn digest_finish_into(hash: &mut H, implementation: Implementation, output: &mut [u8])
  {
    use core::mem::transmute;

    use crate::hazmat::sha::Variant::*;
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha(Sha1) => unsafe { transmute::<&mut H, &mut sha::Sha1>(hash) }.finish_into(implementation, output),
      | Variant::Sha(Sha224) => unsafe { transmute::<&mut H, &mut sha::Sha224>(hash) }.finish_into(implementation, output),
      | Variant::Sha(Sha256) => unsafe { transmute::<&mut H, &mut sha::Sha256>(hash) }.finish_into(implementation, output),
      | Variant::Sha(Sha384) => unsafe { transmute::<&mut H, &mut sha::Sha384>(hash) }.finish_into(implementation, output),
      | Variant::Sha(Sha512) => unsafe { transmute::<&mut H, &mut sha::Sha512>(hash) }.finish_into(implementation, output),
      | Variant::Sha(Sha512_224) => unsafe { transmute::<&mut H, &mut sha::Sha512_224>(hash) }.finish_into(implementation, output),
      | Variant::Sha(Sha512_256) => unsafe { transmute::<&mut H, &mut sha::Sha512_256>(hash) }.finish_into(implementation, output),
    }
  }

  fn digest_finish_sliced(hash: &mut H, implementation: Implementation) -> &[u8]
  {
    use core::mem::transmute;

    use crate::hazmat::sha::Variant::*;
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha(Sha1) => unsafe { transmute::<&mut H, &mut sha::Sha1>(hash) }.finish_sliced(implementation),
      | Variant::Sha(Sha224) => unsafe { transmute::<&mut H, &mut sha::Sha224>(hash) }.finish_sliced(implementation),
      | Variant::Sha(Sha256) => unsafe { transmute::<&mut H, &mut sha::Sha256>(hash) }.finish_sliced(implementation),
      | Variant::Sha(Sha384) => unsafe { transmute::<&mut H, &mut sha::Sha384>(hash) }.finish_sliced(implementation),
      | Variant::Sha(Sha512) => unsafe { transmute::<&mut H, &mut sha::Sha512>(hash) }.finish_sliced(implementation),
      | Variant::Sha(Sha512_224) => unsafe { transmute::<&mut H, &mut sha::Sha512_224>(hash) }.finish_sliced(implementation),
      | Variant::Sha(Sha512_256) => unsafe { transmute::<&mut H, &mut sha::Sha512_256>(hash) }.finish_sliced(implementation),
    }
  }

  pub fn with_key<K: AsRef<[u8]>>(implementation: Implementation, key: K) -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.set_key(implementation, key);
    unsafe { ctx.assume_init() }
  }

  pub fn set_key<K: AsRef<[u8]>>(&mut self, implementation: Implementation, key: K)
  {
    let key = key.as_ref();
    Self::digest_reset(&mut self.hash);
    self.key = [0; B];
    if key.len() > B {
      Self::digest_update(&mut self.hash, implementation, key);
      Self::digest_finish_into(&mut self.hash, implementation, &mut self.key);
      Self::digest_reset(&mut self.hash);
    } else {
      self.key[0 .. key.len()].copy_from_slice(key);
    }
    for i in 0 .. B {
      self.key[i] ^= 0x36;
    }
    self.x5c = false;
    Self::digest_update(&mut self.hash, implementation, &self.key);
  }

  pub fn reset(&mut self, implementation: Implementation)
  {
    if self.x5c {
      for i in 0 .. B {
        self.key[i] ^= 0x36 ^ 0x5c;
      }
      self.x5c = false;
    }
    Self::digest_reset(&mut self.hash);
    Self::digest_update(&mut self.hash, implementation, &self.key);
  }

  pub fn update<D: AsRef<[u8]>>(&mut self, implementation: Implementation, data: D)
  {
    Self::digest_update(&mut self.hash, implementation, data.as_ref());
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
    Self::digest_finish_into(&mut self.hash, implementation, unsafe { digest.assume_init_mut() });
    Self::digest_reset(&mut self.hash);
    for i in 0 .. B {
      self.key[i] ^= 0x36 ^ 0x5c;
    }
    self.x5c = true;
    Self::digest_update(&mut self.hash, implementation, &self.key);
    Self::digest_update(&mut self.hash, implementation, unsafe { digest.assume_init_ref() });
  }

  pub fn finish_into(&mut self, implementation: Implementation, output: &mut [u8])
  {
    self.finish_raw(implementation);
    Self::digest_finish_into(&mut self.hash, implementation, output);
  }

  pub fn finish_sliced(&mut self, implementation: Implementation) -> &[u8]
  {
    self.finish_raw(implementation);
    Self::digest_finish_sliced(&mut self.hash, implementation)
  }

  pub fn oneshot<K: AsRef<[u8]>, D: AsRef<[u8]>>(implementation: Implementation, key: K, data: D) -> [u8; O]
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish(implementation)
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn oneshot_boxed<K: AsRef<[u8]>, D: AsRef<[u8]>>(implementation: Implementation, key: K, data: D) -> Box<[u8]>
  {
    let mut ctx = Self::with_key(implementation, key);
    ctx.update(implementation, data);
    ctx.finish_boxed(implementation)
  }

  pub fn oneshot_into<K: AsRef<[u8]>, D: AsRef<[u8]>>(
    implementation: Implementation,
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
