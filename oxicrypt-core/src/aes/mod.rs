#![allow(non_upper_case_globals)]

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
