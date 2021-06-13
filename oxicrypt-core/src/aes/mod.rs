#![allow(non_upper_case_globals)]

use cfg_if::cfg_if;

pub type AesExpandKey = unsafe fn(key: *const u8, key_schedule: *mut u8);
pub type AesInverseKey = unsafe fn(key_schedule: *mut u8);
pub type AesEncrypt = unsafe fn(block: *mut u8, key_schedule: *const u8);
pub type AesDecrypt = unsafe fn(block: *mut u8, key_schedule: *const u8);

cfg_if! {
  if #[cfg(all(
       any(target_arch = "x86", target_arch = "x86_64"),
       feature = "aesni",
       target_feature = "aes",
       target_feature = "avx"
     ))] {
    pub static aes128_expand_key: AesExpandKey = aes128_expand_key_x86_avx_aesni;
    pub static aes192_expand_key: AesExpandKey = aes192_expand_key_x86_avx_aesni;
    pub static aes256_expand_key: AesExpandKey = aes256_expand_key_x86_avx_aesni;

    pub static aes128_inverse_key: AesInverseKey = aes128_inverse_key_x86_avx_aesni;
    pub static aes192_inverse_key: AesInverseKey = aes192_inverse_key_x86_avx_aesni;
    pub static aes256_inverse_key: AesInverseKey = aes256_inverse_key_x86_avx_aesni;

    pub static aes128_encrypt: AesEncrypt = aes128_encrypt_x86_avx_aesni;
    pub static aes192_encrypt: AesEncrypt = aes192_encrypt_x86_avx_aesni;
    pub static aes256_encrypt: AesEncrypt = aes256_encrypt_x86_avx_aesni;

    pub static aes128_decrypt: AesDecrypt = aes128_decrypt_x86_avx_aesni;
    pub static aes192_decrypt: AesDecrypt = aes192_decrypt_x86_avx_aesni;
    pub static aes256_decrypt: AesDecrypt = aes256_decrypt_x86_avx_aesni;
  } else if #[cfg(all(
              any(target_arch = "x86", target_arch = "x86_64"),
              feature = "aesni",
              target_feature = "aes"
            ))] {
    pub static aes128_expand_key: AesExpandKey = aes128_expand_key_x86_aesni;
    pub static aes192_expand_key: AesExpandKey = aes192_expand_key_x86_aesni;
    pub static aes256_expand_key: AesExpandKey = aes256_expand_key_x86_aesni;

    pub static aes128_inverse_key: AesInverseKey = aes128_inverse_key_x86_aesni;
    pub static aes192_inverse_key: AesInverseKey = aes192_inverse_key_x86_aesni;
    pub static aes256_inverse_key: AesInverseKey = aes256_inverse_key_x86_aesni;

    pub static aes128_encrypt: AesEncrypt = aes128_encrypt_x86_aesni;
    pub static aes192_encrypt: AesEncrypt = aes192_encrypt_x86_aesni;
    pub static aes256_encrypt: AesEncrypt = aes256_encrypt_x86_aesni;

    pub static aes128_decrypt: AesDecrypt = aes128_decrypt_x86_aesni;
    pub static aes192_decrypt: AesDecrypt = aes192_decrypt_x86_aesni;
    pub static aes256_decrypt: AesDecrypt = aes256_decrypt_x86_aesni;
  } else {
    pub static aes128_expand_key: AesExpandKey = aes128_expand_key_lut;
    pub static aes192_expand_key: AesExpandKey = aes192_expand_key_lut;
    pub static aes256_expand_key: AesExpandKey = aes256_expand_key_lut;

    pub static aes128_inverse_key: AesInverseKey = aes128_inverse_key_lut;
    pub static aes192_inverse_key: AesInverseKey = aes192_inverse_key_lut;
    pub static aes256_inverse_key: AesInverseKey = aes256_inverse_key_lut;

    pub static aes128_encrypt: AesEncrypt = aes128_encrypt_lut;
    pub static aes192_encrypt: AesEncrypt = aes192_encrypt_lut;
    pub static aes256_encrypt: AesEncrypt = aes256_encrypt_lut;

    pub static aes128_decrypt: AesDecrypt = aes128_decrypt_lut;
    pub static aes192_decrypt: AesDecrypt = aes192_decrypt_lut;
    pub static aes256_decrypt: AesDecrypt = aes256_decrypt_lut;
  }
}

mod aes_lut;

// Expand key.
pub use aes_lut::aes128_expand_key_lut;
pub use aes_lut::aes192_expand_key_lut;
pub use aes_lut::aes256_expand_key_lut;
// Inverse key.
pub use aes_lut::aes128_inverse_key_lut;
pub use aes_lut::aes192_inverse_key_lut;
pub use aes_lut::aes256_inverse_key_lut;
// Encrypt.
pub use aes_lut::aes128_encrypt_lut;
pub use aes_lut::aes192_encrypt_lut;
pub use aes_lut::aes256_encrypt_lut;
// Decrypt.
pub use aes_lut::aes128_decrypt_lut;
pub use aes_lut::aes192_decrypt_lut;
pub use aes_lut::aes256_decrypt_lut;

// ((x86 || x86_64) && aesni) || doc
#[cfg(any(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"), doc))]
mod aes_x86_aesni;

cfg_if! {
  // (x86 || x86_64) && aesni
  if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni"))] {
    cfg_if! {
      if #[cfg(not(target_feature = "avx"))] {
        // Expand key.
        pub use aes_x86_aesni::aes128_expand_key_x86_aesni;
        pub use aes_x86_aesni::aes192_expand_key_x86_aesni;
        pub use aes_x86_aesni::aes256_expand_key_x86_aesni;

        // Inverse key.
        pub use aes_x86_aesni::aes128_inverse_key_x86_aesni;
        pub use aes_x86_aesni::aes192_inverse_key_x86_aesni;
        pub use aes_x86_aesni::aes256_inverse_key_x86_aesni;

        // Encrypt.
        pub use aes_x86_aesni::aes128_encrypt_x86_aesni;
        pub use aes_x86_aesni::aes192_encrypt_x86_aesni;
        pub use aes_x86_aesni::aes256_encrypt_x86_aesni;

        // Decrypt.
        pub use aes_x86_aesni::aes128_decrypt_x86_aesni;
        pub use aes_x86_aesni::aes192_decrypt_x86_aesni;
        pub use aes_x86_aesni::aes256_decrypt_x86_aesni;
      }
    }

    // Expand key.
    pub use aes_x86_aesni::aes128_expand_key_x86_avx_aesni;
    pub use aes_x86_aesni::aes192_expand_key_x86_avx_aesni;
    pub use aes_x86_aesni::aes256_expand_key_x86_avx_aesni;

    // Inverse key.
    pub use aes_x86_aesni::aes128_inverse_key_x86_avx_aesni;
    pub use aes_x86_aesni::aes192_inverse_key_x86_avx_aesni;
    pub use aes_x86_aesni::aes256_inverse_key_x86_avx_aesni;

    // Encrypt.
    pub use aes_x86_aesni::aes128_encrypt_x86_avx_aesni;
    pub use aes_x86_aesni::aes192_encrypt_x86_avx_aesni;
    pub use aes_x86_aesni::aes256_encrypt_x86_avx_aesni;

    // Decrypt.
    pub use aes_x86_aesni::aes128_decrypt_x86_avx_aesni;
    pub use aes_x86_aesni::aes192_decrypt_x86_avx_aesni;
    pub use aes_x86_aesni::aes256_decrypt_x86_avx_aesni;
  }
}
