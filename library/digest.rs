//! Common digest object.

use core::fmt::Debug;
use core::mem::transmute;
use core::mem::MaybeUninit;

use crate::sha;
use crate::Control;
use crate::Implementation;

enum Variant
{
  Sha1,
  Sha224,
  Sha256,
  Sha384,
  Sha512,
  Sha512_224,
  Sha512_256,
}

/// Digest context.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Digest<D, const M: u64, const O: usize>
where
  D: Debug + Clone + Copy,
{
  inner: D,
}

/// SHA-1
pub type Sha1 = Digest<sha::Sha1, 0x5ba_1, 20>;
/// SHA-224
pub type Sha224 = Digest<sha::Sha224, 0x5ba_224, 28>;
/// SHA-256
pub type Sha256 = Digest<sha::Sha256, 0x5ba_256, 32>;
/// SHA-384
pub type Sha384 = Digest<sha::Sha384, 0x5ba_384, 48>;
/// SHA-512
pub type Sha512 = Digest<sha::Sha512, 0x5ba_512, 64>;
/// SHA-512/224
pub type Sha512_224 = Digest<sha::Sha512_224, 0x5ba_512_224, 28>;
/// SHA-512/256
pub type Sha512_256 = Digest<sha::Sha512_256, 0x5ba_512_256, 32>;

impl<D, const M: u64, const O: usize> Default for Digest<D, M, O>
where
  D: Debug + Clone + Copy,
{
  fn default() -> Self
  {
    Self::new()
  }
}

impl<D, const M: u64, const O: usize> core::hash::Hasher for Digest<D, M, O>
where
  D: Debug + Clone + Copy,
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
impl<D, const M: u64, const O: usize> std::io::Write for Digest<D, M, O>
where
  D: Debug + Clone + Copy,
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

impl<D, const M: u64, const O: usize> Digest<D, M, O>
where
  D: Debug + Clone + Copy,
{
  pub const BLOCK_LEN: usize = match Self::V {
    | Variant::Sha1 | Variant::Sha224 | Variant::Sha256 => 64,
    | Variant::Sha384 | Variant::Sha512 | Variant::Sha512_224 | Variant::Sha512_256 => 128,
  };
  pub const DIGEST_LEN: usize = match Self::V {
    | Variant::Sha1 => 20,
    | Variant::Sha224 => 28,
    | Variant::Sha256 => 32,
    | Variant::Sha384 => 48,
    | Variant::Sha512 => 64,
    | Variant::Sha512_224 => 28,
    | Variant::Sha512_256 => 32,
  };
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

  pub fn update(&mut self, data: &[u8])
  {
    self.update_impl(Control::get_global_implementation(), data);
  }

  pub fn update_impl(&mut self, implementation: Implementation, data: &[u8])
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.update_impl(implementation, data),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.update_impl(implementation, data),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.update_impl(implementation, data),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.update_impl(implementation, data),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.update_impl(implementation, data),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.update_impl(implementation, data),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.update_impl(implementation, data),
    };
  }

  pub fn finish_sliced<'context>(&'context mut self) -> &'context [u8]
  {
    self.finish_sliced_impl(Control::get_global_implementation())
  }

  pub fn finish_sliced_impl<'context>(&'context mut self, implementation: Implementation) -> &'context [u8]
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.finish_sliced_impl(implementation),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.finish_sliced_impl(implementation),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.finish_sliced_impl(implementation),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.finish_sliced_impl(implementation),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.finish_sliced_impl(implementation),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.finish_sliced_impl(implementation),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.finish_sliced_impl(implementation),
    }
  }

  pub fn finish(&mut self) -> [u8; O]
  {
    self.finish_impl(Control::get_global_implementation())
  }

  pub fn finish_impl(&mut self, implementation: Implementation) -> [u8; O]
  {
    let mut digest: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    unsafe { digest.assume_init_mut() }.copy_from_slice(&self.finish_sliced_impl(implementation)[0 .. O]);
    unsafe { digest.assume_init() }
  }

  pub fn finish_into(&mut self, output: &mut [u8])
  {
    self.finish_into_impl(Control::get_global_implementation(), output);
  }

  pub fn finish_into_impl(&mut self, implementation: Implementation, output: &mut [u8])
  {
    #[rustfmt::skip]
    match Self::V {
      | Variant::Sha1 => unsafe { transmute::<&mut D, &mut sha::Sha1>(&mut self.inner) }.finish_into_impl(implementation, output),
      | Variant::Sha224 => unsafe { transmute::<&mut D, &mut sha::Sha224>(&mut self.inner) }.finish_into_impl(implementation, output),
      | Variant::Sha256 => unsafe { transmute::<&mut D, &mut sha::Sha256>(&mut self.inner) }.finish_into_impl(implementation, output),
      | Variant::Sha384 => unsafe { transmute::<&mut D, &mut sha::Sha384>(&mut self.inner) }.finish_into_impl(implementation, output),
      | Variant::Sha512 => unsafe { transmute::<&mut D, &mut sha::Sha512>(&mut self.inner) }.finish_into_impl(implementation, output),
      | Variant::Sha512_224 => unsafe { transmute::<&mut D, &mut sha::Sha512_224>(&mut self.inner) }.finish_into_impl(implementation, output),
      | Variant::Sha512_256 => unsafe { transmute::<&mut D, &mut sha::Sha512_256>(&mut self.inner) }.finish_into_impl(implementation, output),
    }
  }
}
