#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

/// AES variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant
{
  /// AES-128
  Aes128,
  /// AES-192
  Aes192,
  /// AES-256
  Aes256,
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

impl Variant
{
  /// Number of rounds.
  ///
  /// * AES-128 - `10`
  /// * AES-192 - `12`
  /// * AES-256 - `14`
  pub const fn rounds(variant: Self) -> usize
  {
    match variant {
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
  pub const fn key_len(variant: Self) -> usize
  {
    match variant {
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
  pub const fn key_schedule_len(variant: Self) -> usize
  {
    match variant {
      | Self::Aes128 => 176,
      | Self::Aes192 => 208,
      | Self::Aes256 => 240,
    }
  }
}

/// AES implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation
{
  /// Look-up table implementation.
  Lut,
  /// Hardware accelerated version of AES for x86.
  #[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
  #[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
  Aesni,
}

impl Implementation
{
  pub const fn best() -> Self
  {
    #[cfg(all(
      any(target_arch = "x86", target_arch = "x86_64"),
      feature = "aesni",
      target_feature = "aes"
    ))]
    {
      Self::Aesni
    }
    #[cfg(not(all(
      any(target_arch = "x86", target_arch = "x86_64"),
      feature = "aesni",
      target_feature = "aes"
    )))]
    {
      Self::Lut
    }
  }

  pub const fn expand_key<const V: Variant>(implementation: Self) -> unsafe fn(*const u8, *mut u8)
  {
    match implementation {
      | Self::Lut => generic::aes_expand_key::<V>,
      #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
      | Self::Aesni => aesni::aes_expand_key::<V>,
    }
  }

  pub const fn inverse_key<const V: Variant>(implementation: Self) -> unsafe fn(*mut u8)
  {
    match implementation {
      | Self::Lut => generic::aes_inverse_key::<V>,
      #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
      | Self::Aesni => aesni::aes_inverse_key::<V>,
    }
  }

  pub const fn encrypt<const V: Variant>(implementation: Self) -> unsafe fn(*mut u8, *const u8)
  {
    match implementation {
      | Self::Lut => generic::aes_encrypt::<V>,
      #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
      | Self::Aesni => aesni::aes_encrypt::<V>,
    }
  }

  pub const fn decrypt<const V: Variant>(implementation: Self) -> unsafe fn(*mut u8, *const u8)
  {
    match implementation {
      | Self::Lut => generic::aes_decrypt::<V>,
      #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
      | Self::Aesni => aesni::aes_decrypt::<V>,
    }
  }
}

pub struct Control;

impl Control
{
  #[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
  #[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
  pub fn is_aesni_available() -> bool
  {
    std_detect::is_x86_feature_detected!("aes")
  }
}

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
mod aesni;
mod lut;

pub mod generic
{
  pub use super::lut::aes_expand_key;
  pub use super::lut::aes_inverse_key;
  pub use super::lut::aes_encrypt;
  pub use super::lut::aes_decrypt;
}

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub mod x86
{
  pub use super::aesni::aes_expand_key;
  pub use super::aesni::aes_inverse_key;
  pub use super::aesni::aes_encrypt;
  pub use super::aesni::aes_decrypt;
}
