//! High level SHA API.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::cmp::min;
use core::intrinsics::copy_nonoverlapping;
use core::mem::size_of;
use core::mem::MaybeUninit;

use crate::hazmat::sha;
use crate::hazmat::sha::initial_state;
use crate::hazmat::sha::Variant;
use crate::Implementation;

/// SHA context.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Sha<const O: usize, const S: usize, const B: usize>
{
  h: [u8; S],
  block: [u8; B],
  len: u64,
  blocklen: usize,
}

/// SHA-1 context.
pub type Sha1 = Sha<20, 20, 64>;
/// SHA-224 context.
pub type Sha224 = Sha<28, 32, 64>;
/// SHA-256 context.
pub type Sha256 = Sha<32, 32, 64>;
/// SHA-384 context.
pub type Sha384 = Sha<48, 64, 128>;
/// SHA-512 context.
pub type Sha512 = Sha<64, 64, 128>;
/// SHA-512/224 context.
pub type Sha512_224 = Sha<28, 64, 128>;
/// SHA-512/256 context.
pub type Sha512_256 = Sha<32, 64, 128>;

impl<const O: usize, const S: usize, const B: usize> Default for Sha<O, S, B>
{
  fn default() -> Self
  {
    Self::new()
  }
}

impl<const O: usize, const S: usize, const B: usize> Sha<O, S, B>
{
  /// Inner block size in bytes.
  pub const BLOCK_LEN: usize = B;
  /// Digest size in bytes.
  pub const DIGEST_LEN: usize = O;
  /// Inner state size in bytes.
  pub const STATE_LEN: usize = S;
  const V: Variant = match (O, S, B) {
    | (20, 20, 64) => Variant::Sha1,
    | (28, 32, 64) => Variant::Sha224,
    | (32, 32, 64) => Variant::Sha256,
    | (48, 64, 128) => Variant::Sha384,
    | (64, 64, 128) => Variant::Sha512,
    | (28, 64, 128) => Variant::Sha512_224,
    | (32, 64, 128) => Variant::Sha512_256,
    | _ => unsafe { core::hint::unreachable_unchecked() },
  };

  /// Create a new SHA context.
  pub const fn new() -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.reset();
    unsafe { ctx.assume_init() }
  }

  /// Reset a context to its original state.
  ///
  /// It is useful when processing multiple types of data without creating a new context each time.
  pub const fn reset(&mut self)
  {
    self.h = unsafe { initial_state::<S>(Self::V) };
    self.len = 0;
    self.blocklen = 0;
  }

  unsafe fn compress(&mut self, implementation: Implementation)
  {
    match implementation {
      | _ => match Self::V {
        | Variant::Sha1 => sha::generic::sha1_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
        | Variant::Sha224 => sha::generic::sha256_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
        | Variant::Sha256 => sha::generic::sha256_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
        | Variant::Sha384 => sha::generic::sha512_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
        | Variant::Sha512 => sha::generic::sha512_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
        | Variant::Sha512_224 => sha::generic::sha512_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
        | Variant::Sha512_256 => sha::generic::sha512_compress(self.h.as_mut_ptr(), self.block.as_ptr()),
      },
    }
  }

  /// Update the state of the context.
  pub fn update<D: AsRef<[u8]>>(&mut self, implementation: Implementation, data: D)
  {
    let mut data = data.as_ref();
    while !data.is_empty() {
      let emptyspace = Variant::block_len(Self::V) - self.blocklen;
      if emptyspace >= data.len() {
        let newblocklen = self.blocklen + data.len();
        self.block[self.blocklen .. newblocklen].copy_from_slice(data);
        self.blocklen = newblocklen;
        data = &data[0 .. 0];
      } else {
        self.block[self.blocklen .. Variant::block_len(Self::V)].copy_from_slice(&data[0 .. emptyspace]);
        self.blocklen = Variant::block_len(Self::V);
        data = &data[emptyspace ..];
      }
      if self.blocklen == Variant::block_len(Self::V) {
        unsafe { self.compress(implementation) };
        self.blocklen = 0;
        self.len += Variant::block_len(Self::V) as u64;
      }
    }
  }

  fn finish_raw(&mut self, implementation: Implementation)
  {
    self.block[self.blocklen] = 0b10000000;
    self.len += self.blocklen as u64;
    self.blocklen += 1;

    if self.blocklen > (Variant::block_len(Self::V) - Variant::pad_len(Self::V)) {
      self.block[self.blocklen ..].fill(0);
      unsafe { self.compress(implementation) };
      self.blocklen = 0;
    }

    self.block[self.blocklen .. (Variant::block_len(Self::V) - 8)].fill(0);
    self.len *= 8;
    self.len = self.len.to_be();
    self.block[(Variant::block_len(Self::V) - 8) .. Variant::block_len(Self::V)]
      .copy_from_slice(&self.len.to_ne_bytes());
    unsafe { self.compress(implementation) };

    #[cfg(target_endian = "little")]
    match Self::V {
      | Variant::Sha1 | Variant::Sha224 | Variant::Sha256 => {
        for i in 0 .. Variant::state_len(Self::V) / size_of::<u32>() {
          let p = unsafe { self.h.as_mut_ptr().cast::<u32>().add(i) };
          unsafe { *p = u32::to_be(*p) };
        }
      }
      | Variant::Sha384 | Variant::Sha512 | Variant::Sha512_224 | Variant::Sha512_256 => {
        for i in 0 .. Variant::state_len(Self::V) / size_of::<u64>() {
          let p = unsafe { self.h.as_mut_ptr().cast::<u64>().add(i) };
          unsafe { *p = u64::to_be(*p) };
        }
      }
    }
  }

  /// Compute and return the resulting digest value.
  ///
  /// # Note
  ///
  /// This function does not consume the context. Meaning that the context can be used after
  /// finishing, but you need to call [`reset`](`Self::reset`) before doing so. Failing to call
  /// `reset` will result in undefined behaviour.
  pub fn finish(&mut self, implementation: Implementation) -> [u8; O]
  {
    let mut output: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    self.finish_into(implementation, unsafe { output.assume_init_mut() });
    unsafe { output.assume_init() }
  }

  /// Same as [`finish`](`Self::finish`), but returns the result in a [`Box`].
  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn finish_boxed(&mut self, implementation: Implementation) -> Box<[u8]>
  {
    let mut output = unsafe { Box::new_uninit_slice(Variant::digest_len(Self::V)).assume_init() };
    self.finish_into(implementation, &mut output);
    output
  }

  /// Same as [`finish`](`Self::finish`), but you need to provide a mutable slice to put the data
  /// into.
  ///
  /// # Note
  ///
  /// Size of `output` can be anything. Providing a slice with a smaller size than what is needed
  /// by this context will result in the truncation of the resulting digest. Providing a slice with
  /// a larger size than what is needed by this context will result in only the first `N` bytes of
  /// the slice being affected, where `N` is the digest length of the particular SHA algorithm.
  pub fn finish_into(&mut self, implementation: Implementation, output: &mut [u8])
  {
    self.finish_raw(implementation);
    unsafe {
      copy_nonoverlapping(
        self.h.as_ptr(),
        output.as_mut_ptr(),
        min(output.len(), Variant::digest_len(Self::V)),
      )
    };
  }

  /// Same as [`finish`](`Self::finish`), but returns a reference to the inner state, which
  /// contains the digest.
  ///
  /// # Note
  ///
  /// Because this reference points to the state stored in the context itself, calling a function
  /// that mutates the context will nullify the validity of the digest pointed by this reference.
  /// Rust compiler should recognize this and abort compilation.
  pub fn finish_sliced(&mut self, implementation: Implementation) -> &[u8]
  {
    self.finish_raw(implementation);
    &self.h[0 .. O]
  }

  /// Convenience function that creates a context, updates it and returns the resulting digest.
  pub fn oneshot<D: AsRef<[u8]>>(implementation: Implementation, data: D) -> [u8; O]
  {
    let mut ctx = Self::new();
    ctx.update(implementation, data);
    ctx.finish(implementation)
  }

  /// Same as [`oneshot`](`Self::oneshot`), but uses [`finish_boxed`](`Self::finish_boxed`).
  #[cfg(any(feature = "alloc", doc))]
  #[doc(cfg(any(feature = "alloc", feature = "std")))]
  pub fn oneshot_boxed<D: AsRef<[u8]>>(implementation: Implementation, data: D) -> Box<[u8]>
  {
    let mut ctx = Self::new();
    ctx.update(implementation, data);
    ctx.finish_boxed(implementation)
  }

  /// Same as [`oneshot`](`Self::oneshot`), but uses [`finish_into`](`Self::finish_into`).
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

  fn test<const O: usize, const S: usize, const B: usize>(tests: &[(&str, &str, usize)])
  {
    let i = Implementation::fastest_rt();
    let mut ctx = Sha::<O, S, B>::new();
    for (md, msg, _) in tests {
      let mdb = hex::decode(md).unwrap();
      let msgb = hex::decode(msg).unwrap();

      ctx.update(i, &msgb);
      let digest = ctx.finish(i);
      assert_eq!(mdb, digest);
      ctx.reset();

      ctx.update(i, &msgb);
      let digest = ctx.finish_sliced(i);
      assert_eq!(mdb, digest);
      ctx.reset();
    }
  }

  #[test]
  fn sha1()
  {
    test::<20, 20, 64>(SHA1);
  }

  #[test]
  fn sha224()
  {
    test::<28, 32, 64>(SHA224);
  }

  #[test]
  fn sha256()
  {
    test::<32, 32, 64>(SHA256);
  }

  #[test]
  fn sha384()
  {
    test::<48, 64, 128>(SHA384);
  }

  #[test]
  fn sha512()
  {
    test::<64, 64, 128>(SHA512);
  }

  #[test]
  fn sha512_224()
  {
    test::<28, 64, 128>(SHA512_224);
  }

  #[test]
  fn sha512_256()
  {
    test::<32, 64, 128>(SHA512_256);
  }
}
