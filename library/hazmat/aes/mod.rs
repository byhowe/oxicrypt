#[cfg(any(any(target_arch = "x86", target_arch = "x86_64"), doc))]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub mod aesni;
pub mod lut;

use super::Implementation;

/// Pointers to unsafe AES functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine
{
  expand_key: unsafe fn(*const u8, *mut u8),
  inverse_key: unsafe fn(*mut u8),
  encrypt1: unsafe fn(*mut u8, *const u8),
  decrypt1: unsafe fn(*mut u8, *const u8),
}

impl Engine
{
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E128_AESNI: Self = unsafe { Self::new(Variant::Aes128, Implementation::AES) };
  const E128_LUT: Self = unsafe { Self::new(Variant::Aes128, Implementation::new()) };
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E192_AESNI: Self = unsafe { Self::new(Variant::Aes192, Implementation::AES) };
  const E192_LUT: Self = unsafe { Self::new(Variant::Aes192, Implementation::new()) };
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E256_AESNI: Self = unsafe { Self::new(Variant::Aes256, Implementation::AES) };
  const E256_LUT: Self = unsafe { Self::new(Variant::Aes256, Implementation::new()) };

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
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match variant {
        | Variant::Aes128 => Self {
          expand_key: aesni::aes128_expand_key,
          inverse_key: aesni::aes128_inverse_key,
          encrypt1: aesni::aes128_encrypt1,
          decrypt1: aesni::aes128_decrypt1,
        },
        | Variant::Aes192 => Self {
          expand_key: aesni::aes192_expand_key,
          inverse_key: aesni::aes192_inverse_key,
          encrypt1: aesni::aes192_encrypt1,
          decrypt1: aesni::aes192_decrypt1,
        },
        | Variant::Aes256 => Self {
          expand_key: aesni::aes256_expand_key,
          inverse_key: aesni::aes256_inverse_key,
          encrypt1: aesni::aes256_encrypt1,
          decrypt1: aesni::aes256_decrypt1,
        },
      },
      | _ => match variant {
        | Variant::Aes128 => Self {
          expand_key: lut::aes128_expand_key,
          inverse_key: lut::aes128_inverse_key,
          encrypt1: lut::aes128_encrypt1,
          decrypt1: lut::aes128_decrypt1,
        },
        | Variant::Aes192 => Self {
          expand_key: lut::aes192_expand_key,
          inverse_key: lut::aes192_inverse_key,
          encrypt1: lut::aes192_encrypt1,
          decrypt1: lut::aes192_decrypt1,
        },
        | Variant::Aes256 => Self {
          expand_key: lut::aes256_expand_key,
          inverse_key: lut::aes256_inverse_key,
          encrypt1: lut::aes256_encrypt1,
          decrypt1: lut::aes256_decrypt1,
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
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match variant {
        | Variant::Aes128 => &Self::E128_AESNI,
        | Variant::Aes192 => &Self::E192_AESNI,
        | Variant::Aes256 => &Self::E256_AESNI,
      },
      | _ => match variant {
        | Variant::Aes128 => &Self::E128_LUT,
        | Variant::Aes192 => &Self::E192_LUT,
        | Variant::Aes256 => &Self::E256_LUT,
      },
    }
  }

  #[allow(clippy::missing_safety_doc)]
  pub unsafe fn expand_key(&self, key: *const u8, key_schedule: *mut u8)
  {
    (self.expand_key)(key, key_schedule);
  }

  #[allow(clippy::missing_safety_doc)]
  pub unsafe fn inverse_key(&self, key_schedule: *mut u8)
  {
    (self.inverse_key)(key_schedule);
  }

  #[allow(clippy::missing_safety_doc)]
  pub unsafe fn encrypt1(&self, block: *mut u8, key_schedule: *const u8)
  {
    (self.encrypt1)(block, key_schedule);
  }

  #[allow(clippy::missing_safety_doc)]
  pub unsafe fn decrypt1(&self, block: *mut u8, key_schedule: *const u8)
  {
    (self.decrypt1)(block, key_schedule);
  }
}

/// AES variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant
{
  /// AES-128
  Aes128,
  /// AES-192
  Aes192,
  /// AES-256
  Aes256,
}

impl Variant
{
  /// Number of rounds.
  ///
  /// * AES-128 - `10`
  /// * AES-192 - `12`
  /// * AES-256 - `14`
  pub const fn rounds(self) -> usize
  {
    match self {
      | Self::Aes128 => 10,
      | Self::Aes192 => 12,
      | Self::Aes256 => 14,
    }
  }

  /// Key length.
  ///
  /// * AES-128 - `16`
  /// * AES-192 - `24`
  /// * AES-256 - `32`
  pub const fn key_len(self) -> usize
  {
    match self {
      | Self::Aes128 => 16,
      | Self::Aes192 => 24,
      | Self::Aes256 => 32,
    }
  }

  /// Key schedule length.
  ///
  /// * AES-128 - `176`
  /// * AES-192 - `208`
  /// * AES-256 - `240`
  pub const fn key_schedule_len(self) -> usize
  {
    match self {
      | Self::Aes128 => 176,
      | Self::Aes192 => 208,
      | Self::Aes256 => 240,
    }
  }
}

impl core::fmt::Display for Variant
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
  {
    match *self {
      | Self::Aes128 => f.write_str("AES-128"),
      | Self::Aes192 => f.write_str("AES-192"),
      | Self::Aes256 => f.write_str("AES-256"),
    }
  }
}
