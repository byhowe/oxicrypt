#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

use std_detect::is_x86_feature_detected;

pub static AES128_LUT: Aes = Aes {
  expand_key_p: generic::aes128_expand_key_lut,
  inverse_key_p: generic::aes128_inverse_key_lut,
  encrypt_p: generic::aes128_encrypt_lut,
  decrypt_p: generic::aes128_decrypt_lut,
};

pub static AES192_LUT: Aes = Aes {
  expand_key_p: generic::aes192_expand_key_lut,
  inverse_key_p: generic::aes192_inverse_key_lut,
  encrypt_p: generic::aes192_encrypt_lut,
  decrypt_p: generic::aes192_decrypt_lut,
};

pub static AES256_LUT: Aes = Aes {
  expand_key_p: generic::aes256_expand_key_lut,
  inverse_key_p: generic::aes256_inverse_key_lut,
  encrypt_p: generic::aes256_encrypt_lut,
  decrypt_p: generic::aes256_decrypt_lut,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub static AES128_AESNI: Aes = Aes {
  expand_key_p: x86::aes128_expand_key_aesni,
  inverse_key_p: x86::aes128_inverse_key_aesni,
  encrypt_p: x86::aes128_encrypt_aesni,
  decrypt_p: x86::aes128_decrypt_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub static AES192_AESNI: Aes = Aes {
  expand_key_p: x86::aes192_expand_key_aesni,
  inverse_key_p: x86::aes192_inverse_key_aesni,
  encrypt_p: x86::aes192_encrypt_aesni,
  decrypt_p: x86::aes192_decrypt_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub static AES256_AESNI: Aes = Aes {
  expand_key_p: x86::aes256_expand_key_aesni,
  inverse_key_p: x86::aes256_inverse_key_aesni,
  encrypt_p: x86::aes256_encrypt_aesni,
  decrypt_p: x86::aes256_decrypt_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub static AES128_AVX_AESNI: Aes = Aes {
  expand_key_p: x86::aes128_expand_key_avx_aesni,
  inverse_key_p: x86::aes128_inverse_key_avx_aesni,
  encrypt_p: x86::aes128_encrypt_avx_aesni,
  decrypt_p: x86::aes128_decrypt_avx_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub static AES192_AVX_AESNI: Aes = Aes {
  expand_key_p: x86::aes192_expand_key_avx_aesni,
  inverse_key_p: x86::aes192_inverse_key_avx_aesni,
  encrypt_p: x86::aes192_encrypt_avx_aesni,
  decrypt_p: x86::aes192_decrypt_avx_aesni,
};

#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
pub static AES256_AVX_AESNI: Aes = Aes {
  expand_key_p: x86::aes256_expand_key_avx_aesni,
  inverse_key_p: x86::aes256_inverse_key_avx_aesni,
  encrypt_p: x86::aes256_encrypt_avx_aesni,
  decrypt_p: x86::aes256_decrypt_avx_aesni,
};

pub enum Variant
{
  Aes128,
  Aes192,
  Aes256,
}

pub struct Control;

impl Control
{
  #[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
  #[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
  pub fn is_aesni() -> bool
  {
    is_x86_feature_detected!("aes")
  }

  #[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
  #[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
  pub fn is_avx_aesni() -> bool
  {
    is_x86_feature_detected!("avx") && is_x86_feature_detected!("aes")
  }

  pub fn best_impl(variant: Variant) -> &'static Aes
  {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))]
    if Self::is_avx_aesni() {
      match variant {
        | Variant::Aes128 => &AES128_AVX_AESNI,
        | Variant::Aes192 => &AES192_AVX_AESNI,
        | Variant::Aes256 => &AES256_AVX_AESNI,
      }
    } else if Self::is_aesni() {
      match variant {
        | Variant::Aes128 => &AES128_AESNI,
        | Variant::Aes192 => &AES192_AESNI,
        | Variant::Aes256 => &AES256_AESNI,
      }
    } else {
      match variant {
        | Variant::Aes128 => &AES128_LUT,
        | Variant::Aes192 => &AES192_LUT,
        | Variant::Aes256 => &AES256_LUT,
      }
    }

    #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
    match variant {
      | Variant::Aes128 => &AES128_LUT,
      | Variant::Aes192 => &AES192_LUT,
      | Variant::Aes256 => &AES256_LUT,
    }
  }
}

pub struct Aes
{
  expand_key_p: unsafe fn(*const u8, *mut u8),
  inverse_key_p: unsafe fn(*mut u8),
  encrypt_p: unsafe fn(*mut u8, *const u8),
  decrypt_p: unsafe fn(*mut u8, *const u8),
}

impl Aes
{
  #[inline]
  pub unsafe fn expand_key(&self, key: *const u8, key_schedule: *mut u8)
  {
    (self.expand_key_p)(key, key_schedule);
  }

  #[inline]
  pub unsafe fn inverse_key(&self, key_schedule: *mut u8)
  {
    (self.inverse_key_p)(key_schedule);
  }

  #[inline]
  pub unsafe fn encrypt(&self, block: *mut u8, key_schedule: *const u8)
  {
    (self.encrypt_p)(block, key_schedule);
  }

  #[inline]
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
