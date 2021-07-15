#[cfg(any(any(target_arch = "x86", target_arch = "x86_64"), doc))]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub mod aesni;
pub mod lut;

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
  const E128_AESNI: Self = unsafe { Self::new(Variant::Aes128, Implementation::Aesni) };
  const E128_LUT: Self = unsafe { Self::new(Variant::Aes128, Implementation::Lut) };
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E192_AESNI: Self = unsafe { Self::new(Variant::Aes192, Implementation::Aesni) };
  const E192_LUT: Self = unsafe { Self::new(Variant::Aes192, Implementation::Lut) };
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E256_AESNI: Self = unsafe { Self::new(Variant::Aes256, Implementation::Aesni) };
  const E256_LUT: Self = unsafe { Self::new(Variant::Aes256, Implementation::Lut) };

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
      | Implementation::Lut => match variant {
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
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => match variant {
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
      | Implementation::Lut => match variant {
        | Variant::Aes128 => &Self::E128_LUT,
        | Variant::Aes192 => &Self::E192_LUT,
        | Variant::Aes256 => &Self::E256_LUT,
      },
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => match variant {
        | Variant::Aes128 => &Self::E128_AESNI,
        | Variant::Aes192 => &Self::E192_AESNI,
        | Variant::Aes256 => &Self::E256_AESNI,
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

/// AES implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "c", repr(C))]
pub enum Implementation
{
  /// Look-up table based implementation.
  ///
  /// This implementation is always available on all platforms.
  Lut = 0,
  /// Hardware accelerated implementation.
  ///
  /// This implementation is only available on x86 based chips that have the AES feature.
  #[cfg(any(any(target_arch = "x86", target_arch = "x86_64"), doc))]
  #[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
  Aesni = 1,
}

impl Implementation
{
  /// Fastest implementation based on compile-time information.
  ///
  /// This will generally return [`Lut`](`Self::Lut`) as it is the generic implementation that is
  /// available on all platforms. If compiled using `RUSTFLAGS='-C target-feature=+aes'` or certain
  /// feature is known to be available during compile-time, then this function will return the
  /// fastest implementation based on that.
  pub const fn fastest() -> Self
  {
    if cfg!(all(
      any(target_arch = "x86", target_arch = "x86_64"),
      target_feature = "aes"
    )) {
      Self::Aesni
    } else {
      Self::Lut
    }
  }

  /// Fastest implementation based on runtime information.
  pub fn fastest_rt() -> Self
  {
    if cfg!(all(
      any(target_arch = "x86", target_arch = "x86_64"),
      target_feature = "aes"
    )) || Self::is_available(Self::Aesni)
    {
      Self::Aesni
    } else {
      Self::Lut
    }
  }

  /// Performs a runtime check for wether or not a certain implementation is available.
  pub fn is_available(self) -> bool
  {
    match self {
      | Implementation::Lut => true,
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => std_detect::is_x86_feature_detected!("aes"),
    }
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
