#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use std_detect::is_x86_feature_detected;
use spin::Lazy;

pub static AES128: Lazy<AesTable> = Lazy::new(|| Control::best_impl(Variant::Aes128));
pub static AES192: Lazy<AesTable> = Lazy::new(|| Control::best_impl(Variant::Aes192));
pub static AES256: Lazy<AesTable> = Lazy::new(|| Control::best_impl(Variant::Aes256));

pub const AES128_LUT: AesTable = AesTable {
  expand_key_p: generic::aes128_expand_key_lut,
  inverse_key_p: generic::aes128_inverse_key_lut,
  encrypt_p: generic::aes128_encrypt_lut,
  decrypt_p: generic::aes128_decrypt_lut,
};

pub const AES192_LUT: AesTable = AesTable {
  expand_key_p: generic::aes192_expand_key_lut,
  inverse_key_p: generic::aes192_inverse_key_lut,
  encrypt_p: generic::aes192_encrypt_lut,
  decrypt_p: generic::aes192_decrypt_lut,
};

pub const AES256_LUT: AesTable = AesTable {
  expand_key_p: generic::aes256_expand_key_lut,
  inverse_key_p: generic::aes256_inverse_key_lut,
  encrypt_p: generic::aes256_encrypt_lut,
  decrypt_p: generic::aes256_decrypt_lut,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub const AES128_AESNI: AesTable = AesTable {
  expand_key_p: x86::aes128_expand_key_aesni,
  inverse_key_p: x86::aes128_inverse_key_aesni,
  encrypt_p: x86::aes128_encrypt_aesni,
  decrypt_p: x86::aes128_decrypt_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub const AES192_AESNI: AesTable = AesTable {
  expand_key_p: x86::aes192_expand_key_aesni,
  inverse_key_p: x86::aes192_inverse_key_aesni,
  encrypt_p: x86::aes192_encrypt_aesni,
  decrypt_p: x86::aes192_decrypt_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub const AES256_AESNI: AesTable = AesTable {
  expand_key_p: x86::aes256_expand_key_aesni,
  inverse_key_p: x86::aes256_inverse_key_aesni,
  encrypt_p: x86::aes256_encrypt_aesni,
  decrypt_p: x86::aes256_decrypt_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub const AES128_AVX_AESNI: AesTable = AesTable {
  expand_key_p: x86::aes128_expand_key_avx_aesni,
  inverse_key_p: x86::aes128_inverse_key_avx_aesni,
  encrypt_p: x86::aes128_encrypt_avx_aesni,
  decrypt_p: x86::aes128_decrypt_avx_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub const AES192_AVX_AESNI: AesTable = AesTable {
  expand_key_p: x86::aes192_expand_key_avx_aesni,
  inverse_key_p: x86::aes192_inverse_key_avx_aesni,
  encrypt_p: x86::aes192_encrypt_avx_aesni,
  decrypt_p: x86::aes192_decrypt_avx_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub const AES256_AVX_AESNI: AesTable = AesTable {
  expand_key_p: x86::aes256_expand_key_avx_aesni,
  inverse_key_p: x86::aes256_inverse_key_avx_aesni,
  encrypt_p: x86::aes256_encrypt_avx_aesni,
  decrypt_p: x86::aes256_decrypt_avx_aesni,
};

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

pub struct Control;

impl Control
{
  #[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
  #[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
  fn is_aesni() -> bool
  {
    is_x86_feature_detected!("aes")
  }

  #[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
  #[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
  fn is_avx_aesni() -> bool
  {
    is_x86_feature_detected!("avx") && is_x86_feature_detected!("aes")
  }

  #[inline(always)]
  pub fn initialize(variant: Variant)
  {
    match variant {
      | Variant::Aes128 => spin::Lazy::force(&AES128),
      | Variant::Aes192 => spin::Lazy::force(&AES192),
      | Variant::Aes256 => spin::Lazy::force(&AES256),
    };
  }

  #[inline(always)]
  pub fn aes_table(variant: Variant) -> &'static AesTable
  {
    match variant {
      | Variant::Aes128 => unsafe { &*AES128.as_mut_ptr() },
      | Variant::Aes192 => unsafe { &*AES192.as_mut_ptr() },
      | Variant::Aes256 => unsafe { &*AES256.as_mut_ptr() },
    }
  }

  pub fn best_impl(variant: Variant) -> AesTable
  {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
    if Self::is_avx_aesni() {
      match variant {
        | Variant::Aes128 => AES128_AVX_AESNI,
        | Variant::Aes192 => AES192_AVX_AESNI,
        | Variant::Aes256 => AES256_AVX_AESNI,
      }
    } else if Self::is_aesni() {
      match variant {
        | Variant::Aes128 => AES128_AESNI,
        | Variant::Aes192 => AES192_AESNI,
        | Variant::Aes256 => AES256_AESNI,
      }
    } else {
      match variant {
        | Variant::Aes128 => AES128_LUT,
        | Variant::Aes192 => AES192_LUT,
        | Variant::Aes256 => AES256_LUT,
      }
    }

    #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
    match variant {
      | Variant::Aes128 => AES128_LUT,
      | Variant::Aes192 => AES192_LUT,
      | Variant::Aes256 => AES256_LUT,
    }
  }
}

pub struct AesTable
{
  expand_key_p: unsafe fn(*const u8, *mut u8),
  inverse_key_p: unsafe fn(*mut u8),
  encrypt_p: unsafe fn(*mut u8, *const u8),
  decrypt_p: unsafe fn(*mut u8, *const u8),
}

impl AesTable
{
  #[inline(always)]
  pub unsafe fn expand_key(&self, key: *const u8, key_schedule: *mut u8)
  {
    (self.expand_key_p)(key, key_schedule);
  }

  #[inline(always)]
  pub unsafe fn inverse_key(&self, key_schedule: *mut u8)
  {
    (self.inverse_key_p)(key_schedule);
  }

  #[inline(always)]
  pub unsafe fn encrypt(&self, block: *mut u8, key_schedule: *const u8)
  {
    (self.encrypt_p)(block, key_schedule);
  }

  #[inline(always)]
  pub unsafe fn decrypt(&self, block: *mut u8, key_schedule: *const u8)
  {
    (self.decrypt_p)(block, key_schedule);
  }
}

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
mod aesni;
mod lut;

pub mod generic
{
  // Expand key.
  pub use super::lut::aes128_expand_key_lut;
  pub use super::lut::aes192_expand_key_lut;
  pub use super::lut::aes256_expand_key_lut;
  // Inverse key.
  pub use super::lut::aes128_inverse_key_lut;
  pub use super::lut::aes192_inverse_key_lut;
  pub use super::lut::aes256_inverse_key_lut;
  // Encrypt.
  pub use super::lut::aes128_encrypt_lut;
  pub use super::lut::aes192_encrypt_lut;
  pub use super::lut::aes256_encrypt_lut;
  // Decrypt.
  pub use super::lut::aes128_decrypt_lut;
  pub use super::lut::aes192_decrypt_lut;
  pub use super::lut::aes256_decrypt_lut;
}

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub mod x86
{
  // Expand key.
  pub use super::aesni::aes128_expand_key_aesni;
  pub use super::aesni::aes192_expand_key_aesni;
  pub use super::aesni::aes256_expand_key_aesni;
  // Inverse key.
  pub use super::aesni::aes128_inverse_key_aesni;
  pub use super::aesni::aes192_inverse_key_aesni;
  pub use super::aesni::aes256_inverse_key_aesni;
  // Encrypt.
  pub use super::aesni::aes128_encrypt_aesni;
  pub use super::aesni::aes192_encrypt_aesni;
  pub use super::aesni::aes256_encrypt_aesni;
  // Decrypt.
  pub use super::aesni::aes128_decrypt_aesni;
  pub use super::aesni::aes192_decrypt_aesni;
  pub use super::aesni::aes256_decrypt_aesni;
  // Expand key.
  pub use super::aesni::aes128_expand_key_avx_aesni;
  pub use super::aesni::aes192_expand_key_avx_aesni;
  pub use super::aesni::aes256_expand_key_avx_aesni;
  // Inverse key.
  pub use super::aesni::aes128_inverse_key_avx_aesni;
  pub use super::aesni::aes192_inverse_key_avx_aesni;
  pub use super::aesni::aes256_inverse_key_avx_aesni;
  // Encrypt.
  pub use super::aesni::aes128_encrypt_avx_aesni;
  pub use super::aesni::aes192_encrypt_avx_aesni;
  pub use super::aesni::aes256_encrypt_avx_aesni;
  // Decrypt.
  pub use super::aesni::aes128_decrypt_avx_aesni;
  pub use super::aesni::aes192_decrypt_avx_aesni;
  pub use super::aesni::aes256_decrypt_avx_aesni;
}
