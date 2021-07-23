//! All things digest.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::mem::transmute;
use core::mem::MaybeUninit;

use crate::sha;
use crate::Implementation;

enum Variant
{
  Sha1 = 0x5ba_1,
  Sha224 = 0x5ba_224,
  Sha256 = 0x5ba_256,
  Sha384 = 0x5ba_384,
  Sha512 = 0x5ba_512,
  Sha512_224 = 0x5ba_512_224,
  Sha512_256 = 0x5ba_512_256,
}

/// Digest context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Digest<D, const M: usize, const O: usize>
{
  inner: D,
}

impl<D, const M: usize, const O: usize> Digest<D, M, O>
{
  const V: Variant = match (M, O) {
    | (0x5ba_1, 20) => Variant::Sha1,
    | (0x5ba_224, 28) => Variant::Sha224,
    | (0x5ba_256, 32) => Variant::Sha256,
    | (0x5ba_384, 48) => Variant::Sha384,
    | (0x5ba_512, 64) => Variant::Sha512,
    | (0x5ba_512_224, 28) => Variant::Sha512_224,
    | (0x5ba_512_256, 32) => Variant::Sha512_256,
    | _ => unsafe { core::hint::unreachable_unchecked() },
  };

  pub const fn new() -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.reset();
    unsafe { ctx.assume_init() }
  }

  pub const fn reset(&mut self)
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.reset(),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.reset(),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.reset(),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.reset(),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.reset(),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.reset(),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.reset(),
    };
  }

  pub fn update<B: AsRef<[u8]>>(&mut self, implementation: Implementation, data: B)
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.update(implementation, data),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.update(implementation, data),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.update(implementation, data),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.update(implementation, data),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.update(implementation, data),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.update(implementation, data),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.update(implementation, data),
    };
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
    let mut output: Box<[u8]> = unsafe { Box::new_uninit_slice(O).assume_init() };
    self.finish_into(implementation, &mut output);
    output
  }

  pub fn finish_into(&mut self, implementation: Implementation, output: &mut [u8])
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.finish_into(implementation, output),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.finish_into(implementation, output),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.finish_into(implementation, output),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.finish_into(implementation, output),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.finish_into(implementation, output),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.finish_into(implementation, output),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.finish_into(implementation, output),
    }
  }

  pub fn finish_sliced(&mut self, implementation: Implementation) -> &[u8]
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.finish_sliced(implementation),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.finish_sliced(implementation),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.finish_sliced(implementation),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.finish_sliced(implementation),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.finish_sliced(implementation),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.finish_sliced(implementation),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.finish_sliced(implementation),
    }
  }
}
