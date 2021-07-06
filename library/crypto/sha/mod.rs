mod sha1_compress_generic;
mod sha256_compress_generic;
mod sha512_compress_generic;

use core::mem;

/// SHA implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(c, repr(C))]
pub enum Implementation
{
  /// Generic implementation.
  ///
  /// This implementation is always available on all platforms.
  Generic = 0,
}

impl Implementation
{
  /// Fastest implementation based on compile-time information.
  ///
  /// Currently returns [`Generic`](`Self::Generic`).
  pub const fn fastest() -> Self
  {
    Self::Generic
  }

  /// Fastest implementation based on runtime information.
  ///
  /// Currently returns [`Generic`](`Self::Generic`).
  pub fn fastest_rt() -> Self
  {
    Self::Generic
  }

  /// Performs a runtime check for wether or not a certain implementation is available.
  pub fn is_available(self) -> bool
  {
    match self {
      | Implementation::Generic => true,
    }
  }
}

/// Pointers to unsafe SHA compression functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine
{
  compress: unsafe fn(*mut u8, *const u8),
}

impl Engine
{
  const E1_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha1 }>(Implementation::Generic) };
  const E224_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha224 }>(Implementation::Generic) };
  const E256_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha256 }>(Implementation::Generic) };
  const E384_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha384 }>(Implementation::Generic) };
  const E512_224_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha512_224 }>(Implementation::Generic) };
  const E512_256_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha512_256 }>(Implementation::Generic) };
  const E512_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha512 }>(Implementation::Generic) };

  /// Returns the appropriate engine for a given implementation.
  ///
  /// # Safety
  ///
  /// Note that this function does not perform any kind of check for wheter a given
  /// implementation is available during runtime. If you try to use an engine with an
  /// implementation that is not available during runtime, it might result in an illegal
  /// instruction signal.
  pub const unsafe fn new<const V: Variant>(implementation: Implementation) -> Self
  {
    match implementation {
      | Implementation::Generic => Engine {
        compress: Sha::<V, { Implementation::Generic }>::compress,
      },
    }
  }

  /// Returns a reference to the appropriate engine for a given implementation.
  ///
  /// # Safety
  ///
  /// Same as [`Engine::new`].
  pub const unsafe fn as_ref<const V: Variant>(implementation: Implementation) -> &'static Self
  {
    match implementation {
      | Implementation::Generic => match V {
        | Variant::Sha1 => &Self::E1_GENERIC,
        | Variant::Sha224 => &Self::E224_GENERIC,
        | Variant::Sha256 => &Self::E256_GENERIC,
        | Variant::Sha384 => &Self::E384_GENERIC,
        | Variant::Sha512 => &Self::E512_GENERIC,
        | Variant::Sha512_224 => &Self::E512_224_GENERIC,
        | Variant::Sha512_256 => &Self::E512_256_GENERIC,
      },
    }
  }

  #[allow(clippy::missing_safety_doc)]
  pub unsafe fn compress(&self, state: *mut u8, block: *const u8)
  {
    (self.compress)(state, block);
  }
}

/// SHA variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant
{
  /// SHA-1
  Sha1,
  /// SHA-224
  Sha224,
  /// SHA-256
  Sha256,
  /// SHA-384
  Sha384,
  /// SHA-512
  Sha512,
  /// SHA-512/224
  Sha512_224,
  /// SHA-512/256
  Sha512_256,
}

impl Variant
{
  /// Padding length.
  ///
  /// * SHA-1 | SHA-224 | SHA-256 - `mem::size_of::<u64>()`
  /// * SHA-384 | SHA-512 | SHA-512/224 | SHA-512/256 - `mem::size_of::<u128>()`
  pub const fn pad_len(self) -> usize
  {
    match self {
      | Self::Sha1 | Self::Sha224 | Self::Sha256 => mem::size_of::<u64>(),
      | Self::Sha384 | Self::Sha512 | Self::Sha512_224 | Self::Sha512_256 => mem::size_of::<u128>(),
    }
  }

  /// State length.
  ///
  /// * SHA-1 - `20`
  /// * SHA-224 | SHA-256 - `32`
  /// * SHA-384 | SHA-512 | SHA-512/224 | SHA-512/256 - `64`
  pub const fn state_len(self) -> usize
  {
    match self {
      | Self::Sha1 => 20,
      | Self::Sha224 | Self::Sha256 => 32,
      | Self::Sha384 | Self::Sha512 | Self::Sha512_224 | Self::Sha512_256 => 64,
    }
  }

  /// Digest length.
  ///
  /// * SHA-1 - `20`
  /// * SHA-224 | SHA-512/224 - `28`
  /// * SHA-256 | SHA-512/256 - `32`
  /// * SHA-384 - `48`
  /// * SHA-512 - `64`
  pub const fn digest_len(self) -> usize
  {
    match self {
      | Self::Sha1 => 20,
      | Self::Sha224 | Self::Sha512_224 => 28,
      | Self::Sha256 | Self::Sha512_256 => 32,
      | Self::Sha384 => 48,
      | Self::Sha512 => 64,
    }
  }

  /// Block length.
  ///
  /// * SHA-1 | SHA-224 | SHA-256 - `64`
  /// * SHA-384 | SHA-512 | SHA-512/224 | SHA-512/256 - `128`
  pub const fn block_len(self) -> usize
  {
    match self {
      | Self::Sha1 | Self::Sha224 | Self::Sha256 => 64,
      | Self::Sha384 | Self::Sha512 | Self::Sha512_224 | Self::Sha512_256 => 128,
    }
  }
}

impl core::fmt::Display for Variant
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
  {
    match *self {
      | Self::Sha1 => f.write_str("SHA-1"),
      | Self::Sha224 => f.write_str("SHA-224"),
      | Self::Sha256 => f.write_str("SHA-256"),
      | Self::Sha384 => f.write_str("SHA-384"),
      | Self::Sha512 => f.write_str("SHA-512"),
      | Self::Sha512_224 => f.write_str("SHA-512/224"),
      | Self::Sha512_256 => f.write_str("SHA-512/256"),
    }
  }
}

/// Core SHA structure that provides all the necessary functions to implement a higher level API.
pub struct Sha<const V: Variant, const I: Implementation>;

impl<const V: Variant, const I: Implementation> Sha<V, I>
{
  /// Same as [`Variant::state_len(V)`](`Variant::state_len`).
  pub const fn state_len() -> usize
  {
    Variant::state_len(V)
  }

  /// Same as [`Variant::digest_len(V)`](`Variant::digest_len`).
  pub const fn digest_len() -> usize
  {
    Variant::digest_len(V)
  }

  /// Same as [`Variant::block_len(V)`](`Variant::block_len`).
  pub const fn block_len() -> usize
  {
    Variant::block_len(V)
  }

  /// Compresses the block into state.
  ///
  /// # Safety
  ///
  /// * `state` must be at least `Variant::state_len(V)` bytes.
  /// * `block` must be at least `Variant::block_len(V)` bytes.
  pub unsafe fn compress(state: *mut u8, block: *const u8)
  {
    match I {
      | Implementation::Generic => match V {
        | Variant::Sha1 => sha1_compress_generic::sha1_compress_generic(state as *mut u32, block),
        | Variant::Sha224 | Variant::Sha256 => {
          sha256_compress_generic::sha256_compress_generic(state as *mut u32, block)
        }
        | Variant::Sha384 | Variant::Sha512 | Variant::Sha512_224 | Variant::Sha512_256 => {
          sha512_compress_generic::sha512_compress_generic(state as *mut u64, block)
        }
      },
    }
  }
}

/// Initial state.
///
/// * SHA-1 - [`H1`]
/// * SHA-224 - [`H224`]
/// * SHA-256 - [`H256`]
/// * SHA-384 - [`H384`]
/// * SHA-512 - [`H512`]
/// * SHA-512_224 - [`H512_224`]
/// * SHA-512_256 - [`H512_256`]
pub const fn initial_state<const V: Variant>() -> [u8; Variant::state_len(V)]
where
  [u8; Variant::state_len(V)]: Sized,
{
  use core::mem::transmute;
  match V {
    | Variant::Sha1 => unsafe { *transmute::<&[u32; 5], &[u8; Variant::state_len(V)]>(&H1) },
    | Variant::Sha224 => unsafe { *transmute::<&[u32; 8], &[u8; Variant::state_len(V)]>(&H224) },
    | Variant::Sha256 => unsafe { *transmute::<&[u32; 8], &[u8; Variant::state_len(V)]>(&H256) },
    | Variant::Sha384 => unsafe { *transmute::<&[u64; 8], &[u8; Variant::state_len(V)]>(&H384) },
    | Variant::Sha512 => unsafe { *transmute::<&[u64; 8], &[u8; Variant::state_len(V)]>(&H512) },
    | Variant::Sha512_224 => unsafe { *transmute::<&[u64; 8], &[u8; Variant::state_len(V)]>(&H512_224) },
    | Variant::Sha512_256 => unsafe { *transmute::<&[u64; 8], &[u8; Variant::state_len(V)]>(&H512_256) },
  }
}

/// Initial state of the SHA-1 algorithm. Use with the SHA-1 compression function.
#[rustfmt::skip]
pub const H1: [u32; 5] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
  0xc3d2e1f0,
];

/// Initial state of the SHA-224 algorithm. Use with the SHA-256 compression function.
#[rustfmt::skip]
pub const H224: [u32; 8] = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];

/// Initial state of the SHA-256 algorithm. Use with the SHA-256 compression function.
#[rustfmt::skip]
pub const H256: [u32; 8] = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

/// Initial state of the SHA-384 algorithm. Use with the SHA-512 compression function.
#[rustfmt::skip]
pub const H384: [u64; 8] = [
  0xcbbb9d5dc1059ed8,
  0x629a292a367cd507,
  0x9159015a3070dd17,
  0x152fecd8f70e5939,
  0x67332667ffc00b31,
  0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7,
  0x47b5481dbefa4fa4,
];

/// Initial state of the SHA-512 algorithm. Use with the SHA-512 compression function.
#[rustfmt::skip]
pub const H512: [u64; 8] = [
  0x6a09e667f3bcc908,
  0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1,
  0x510e527fade682d1,
  0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b,
  0x5be0cd19137e2179,
];

/// Initial state of the SHA-512/224 algorithm. Use with the SHA-512 compression function.
#[rustfmt::skip]
pub const H512_224: [u64; 8] = [
  0x8c3d37c819544da2,
  0x73e1996689dcd4d6,
  0x1dfab7ae32ff9c82,
  0x679dd514582f9fcf,
  0x0f6d2b697bd44da8,
  0x77e36f7304c48942,
  0x3f9d85a86a1d36c8,
  0x1112e6ad91d692a1,
];

/// Initial state of the SHA-512/256 algorithm. Use with the SHA-512 compression function.
#[rustfmt::skip]
pub const H512_256: [u64; 8] = [
  0x22312194fc2bf72c,
  0x9f555fa3c84c64c2,
  0x2393b86b6f53b151,
  0x963877195940eabd,
  0x96283ee2a88effe3,
  0xbe5e1e2553863992,
  0x2b0199fc2c85b8aa,
  0x0eb72ddc81c52ca2,
];
