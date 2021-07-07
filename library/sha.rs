//! High level SHA API.

use core::mem::MaybeUninit;
use core::mem::size_of;
use core::cmp::min;
use core::intrinsics::copy_nonoverlapping;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[doc(inline)]
pub use crate::crypto::sha::Implementation;
#[doc(inline)]
pub use crate::crypto::sha::Variant;
use crate::crypto::sha::Engine;
use crate::crypto::sha::initial_state;

/// SHA context.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(c, repr(C))]
pub struct Sha<const V: Variant>
where
  [u8; Variant::state_len(V)]: Sized,
  [u8; Variant::block_len(V)]: Sized,
{
  h: [u8; Variant::state_len(V)],
  block: [u8; Variant::block_len(V)],
  len: u64,
  blocklen: usize,
}

/// SHA-1 context.
pub type Sha1 = Sha<{ Variant::Sha1 }>;
/// SHA-224 context.
pub type Sha224 = Sha<{ Variant::Sha224 }>;
/// SHA-256 context.
pub type Sha256 = Sha<{ Variant::Sha256 }>;
/// SHA-384 context.
pub type Sha384 = Sha<{ Variant::Sha384 }>;
/// SHA-512 context.
pub type Sha512 = Sha<{ Variant::Sha512 }>;
/// SHA-512_224 context.
pub type Sha512_224 = Sha<{ Variant::Sha512_224 }>;
/// SHA-512_256 context.
pub type Sha512_256 = Sha<{ Variant::Sha512_256 }>;

impl<const V: Variant> Default for Sha<V>
where
  [u8; Variant::state_len(V)]: Sized,
  [u8; Variant::block_len(V)]: Sized,
{
  fn default() -> Self
  {
    Self::new()
  }
}

impl<const V: Variant> Sha<V>
where
  [u8; Variant::state_len(V)]: Sized,
  [u8; Variant::block_len(V)]: Sized,
{
  pub const fn new() -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.reset();
    unsafe { ctx.assume_init() }
  }

  pub const fn reset(&mut self)
  {
    self.h = initial_state::<V>();
    self.block = [0; Variant::block_len(V)];
    self.len = 0;
    self.blocklen = 0;
  }

  pub fn update<D: AsRef<[u8]>>(&mut self, implementation: Implementation, data: D)
  {
    let mut data = data.as_ref();
    while !data.is_empty() {
      let emptyspace = Variant::block_len(V) - self.blocklen;
      if emptyspace >= data.len() {
        let newblocklen = self.blocklen + data.len();
        self.block[self.blocklen .. newblocklen].copy_from_slice(data);
        self.blocklen = newblocklen;
        data = &data[0 .. 0];
      } else {
        self.block[self.blocklen .. Variant::block_len(V)].copy_from_slice(&data[0 .. emptyspace]);
        self.blocklen = Variant::block_len(V);
        data = &data[emptyspace ..];
      }
      if self.blocklen == Variant::block_len(V) {
        unsafe { Engine::as_ref::<V>(implementation).compress(self.h.as_mut_ptr(), self.block.as_ptr()) };
        self.blocklen = 0;
        self.len += Variant::block_len(V) as u64;
      }
    }
  }

  pub fn finish(&mut self, implementation: Implementation) -> [u8; Variant::digest_len(V)]
  {
    let mut output: MaybeUninit<[u8; Variant::digest_len(V)]> = MaybeUninit::uninit();
    self.finish_into(implementation, unsafe { output.assume_init_mut() });
    unsafe { output.assume_init() }
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn finish_boxed(&mut self, implementation: Implementation) -> Box<[u8]>
  {
    let mut output = unsafe { Box::new_uninit_slice(Variant::digest_len(V)).assume_init() };
    self.finish_into(implementation, &mut output);
    output
  }

  pub fn finish_into(&mut self, implementation: Implementation, output: &mut [u8])
  {
    self.block[self.blocklen] = 0b10000000;
    self.len += self.blocklen as u64;
    self.blocklen += 1;

    if self.blocklen > (Variant::block_len(V) - Variant::pad_len(V)) {
      self.block[self.blocklen ..].fill(0);
      unsafe { Engine::as_ref::<V>(implementation).compress(self.h.as_mut_ptr(), self.block.as_ptr()) };
      self.blocklen = 0;
    }

    self.block[self.blocklen .. (Variant::block_len(V) - 8)].fill(0);
    self.len *= 8;
    self.len = self.len.to_be();
    self.block[(Variant::block_len(V) - 8) .. Variant::block_len(V)].copy_from_slice(&self.len.to_ne_bytes());
    unsafe { Engine::as_ref::<V>(implementation).compress(self.h.as_mut_ptr(), self.block.as_ptr()) };

    #[cfg(target_endian = "little")]
    match V {
      | Variant::Sha1 | Variant::Sha224 | Variant::Sha256 => {
        for i in 0 .. Variant::state_len(V) / size_of::<u32>() {
          let p = unsafe { self.h.as_mut_ptr().cast::<u32>().add(i) };
          unsafe { *p = u32::to_be(*p) };
        }
      }
      | Variant::Sha384 | Variant::Sha512 | Variant::Sha512_224 | Variant::Sha512_256 => {
        for i in 0 .. Variant::state_len(V) / size_of::<u64>() {
          let p = unsafe { self.h.as_mut_ptr().cast::<u64>().add(i) };
          unsafe { *p = u64::to_be(*p) };
        }
      }
    }

    unsafe {
      copy_nonoverlapping(
        self.h.as_ptr(),
        output.as_mut_ptr(),
        min(output.len(), Variant::digest_len(V)),
      )
    };
  }

  pub fn oneshot<D: AsRef<[u8]>>(implementation: Implementation, data: D) -> [u8; Variant::digest_len(V)]
  {
    let mut ctx = Self::new();
    ctx.update(implementation, data);
    ctx.finish(implementation)
  }

  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn oneshot_boxed<D: AsRef<[u8]>>(implementation: Implementation, data: D) -> Box<[u8]>
  {
    let mut ctx = Self::new();
    ctx.update(implementation, data);
    ctx.finish_boxed(implementation)
  }

  pub fn oneshot_into<D: AsRef<[u8]>>(implementation: Implementation, data: D, output: &mut [u8])
  {
    let mut ctx = Self::new();
    ctx.update(implementation, data);
    ctx.finish_into(implementation, output);
  }
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::cavp::*;

  fn test<const V: Variant>(tests: &[(&str, &str, usize)])
  where
    [u8; Variant::state_len(V)]: Sized,
    [u8; Variant::block_len(V)]: Sized,
    [u8; Variant::digest_len(V)]: Sized,
  {
    let i = Implementation::fastest_rt();
    let mut ctx = Sha::<V>::new();
    for (md, msg, _) in tests {
      let mdb = hex::decode(md).unwrap();
      let msgb = hex::decode(msg).unwrap();
      ctx.update(i, &msgb);
      let digest = ctx.finish(i);
      ctx.reset();
      assert_eq!(mdb, digest);
    }
  }

  #[test]
  fn sha1()
  {
    test::<{ Variant::Sha1 }>(SHA1);
  }

  #[test]
  fn sha224()
  {
    test::<{ Variant::Sha224 }>(SHA224);
  }

  #[test]
  fn sha256()
  {
    test::<{ Variant::Sha256 }>(SHA256);
  }

  #[test]
  fn sha384()
  {
    test::<{ Variant::Sha384 }>(SHA384);
  }

  #[test]
  fn sha512()
  {
    test::<{ Variant::Sha512 }>(SHA512);
  }

  #[test]
  fn sha512_224()
  {
    test::<{ Variant::Sha512_224 }>(SHA512_224);
  }

  #[test]
  fn sha512_256()
  {
    test::<{ Variant::Sha512_256 }>(SHA512_256);
  }
}
