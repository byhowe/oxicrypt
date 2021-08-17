mod md5_compress_generic;

pub mod generic
{
  pub const unsafe fn md5_compress(state: *mut u8, block: *const u8)
  {
    super::md5_compress_generic::md5_compress_generic(state.cast(), block);
  }
}

use crate::Implementation;

/// Pointers to unsafe MD compression functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine
{
  compress: unsafe fn(*mut u8, *const u8),
}

impl Engine
{
  const MD5_GENERIC: Self = unsafe { Self::new(Variant::Md5, Implementation::new()) };

  /// Returns the appropriate engine for a given implementation.
  ///
  /// # Safety
  ///
  /// Note that this function does not perform any kind of check for wheter a given
  /// implementation is available during runtime. If you try to use an engine with an
  /// implementation that is not available during runtime, it might result in an illegal
  /// instruction signal.
  pub const unsafe fn new(variant: Variant, implementation: Implementation) -> Self
  {
    match implementation {
      | _ => match variant {
        | Variant::Md5 => Self {
          compress: generic::md5_compress,
        },
      },
    }
  }

  /// Returns a reference to the appropriate engine for a given implementation.
  ///
  /// # Safety
  ///
  /// Same as [`Engine::new`].
  pub const unsafe fn as_ref(variant: Variant, implementation: Implementation) -> &'static Self
  {
    match implementation {
      | _ => match variant {
        | Variant::Md5 => &Self::MD5_GENERIC,
      },
    }
  }

  #[allow(clippy::missing_safety_doc)]
  pub unsafe fn compress(&self, state: *mut u8, block: *const u8)
  {
    (self.compress)(state, block);
  }
}

/// MD variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant
{
  /// MD5
  Md5,
}

impl Variant
{
  /// Digest length.
  ///
  /// * MD5 - `16`
  pub const fn digest_len(self) -> usize
  {
    match self {
      | Self::Md5 => 16,
    }
  }

  /// Block length.
  ///
  /// * MD5 - `64`
  pub const fn block_len(self) -> usize
  {
    match self {
      | Self::Md5 => 64,
    }
  }
}

impl core::fmt::Display for Variant
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
  {
    match *self {
      | Self::Md5 => f.write_str("MD5"),
    }
  }
}

/// Initial state of the MD5 algorithm.
#[rustfmt::skip]
pub const H: [u32; 4] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476
];
