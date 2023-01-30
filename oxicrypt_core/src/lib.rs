//! # The Oxicrypt Core Library
//!
//! The Oxicrypt Core Library is a collection of low level cryptography functions that can be used
//! to build a cryptography library. It is the foundation for the the Oxicrypt Cryptography Library
//! which exposes a higher level and a safer API that is built on top of `oxicrypt_core`. This
//! library should not be used on its own as it icludes unsafe functions.

#![no_std]
#![feature(doc_cfg)]
#![feature(generic_const_exprs)]
#![feature(const_mut_refs)]

use cfg_if::cfg_if;

mod aes_lut_aes_core;
mod sha_generic_sha1_compress;
mod sha_generic_sha256_compress;
mod sha_generic_sha512_compress;
mod sha_initial_states;

pub use aes_lut_aes_core::aes_lut_aes128_decrypt1;
pub use aes_lut_aes_core::aes_lut_aes128_encrypt1;
pub use aes_lut_aes_core::aes_lut_aes128_expand_key;
pub use aes_lut_aes_core::aes_lut_aes128_inverse_key;
pub use aes_lut_aes_core::aes_lut_aes192_decrypt1;
pub use aes_lut_aes_core::aes_lut_aes192_encrypt1;
pub use aes_lut_aes_core::aes_lut_aes192_expand_key;
pub use aes_lut_aes_core::aes_lut_aes192_inverse_key;
pub use aes_lut_aes_core::aes_lut_aes256_decrypt1;
pub use aes_lut_aes_core::aes_lut_aes256_encrypt1;
pub use aes_lut_aes_core::aes_lut_aes256_expand_key;
pub use aes_lut_aes_core::aes_lut_aes256_inverse_key;
pub use sha_generic_sha1_compress::sha_generic_sha1_compress;
pub use sha_generic_sha256_compress::sha_generic_sha256_compress;
pub use sha_generic_sha512_compress::sha_generic_sha512_compress;
pub use sha_initial_states::SHA_INITIAL_H1;
pub use sha_initial_states::SHA_INITIAL_H224;
pub use sha_initial_states::SHA_INITIAL_H256;
pub use sha_initial_states::SHA_INITIAL_H384;
pub use sha_initial_states::SHA_INITIAL_H512;
pub use sha_initial_states::SHA_INITIAL_H512_224;
pub use sha_initial_states::SHA_INITIAL_H512_256;

cfg_if! {
  if #[cfg(any(target_arch = "x86", target_arch = "x86_64", doc))] {
    // full set of AES-NI powered aes functions
    mod aes_x86_aesni_aes_encrypt;
    mod aes_x86_aesni_aes_decrypt;
    mod aes_x86_aesni_aes_inverse_key;
    mod aes_x86_aesni_aes_expand_key;

    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes128_encrypt1;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes128_encrypt2;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes128_encrypt4;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes128_encrypt8;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes192_encrypt1;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes192_encrypt2;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes192_encrypt4;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes192_encrypt8;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes256_encrypt1;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes256_encrypt2;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes256_encrypt4;
    pub use aes_x86_aesni_aes_encrypt::aes_x86_aesni_aes256_encrypt8;

    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes128_decrypt1;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes128_decrypt2;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes128_decrypt4;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes128_decrypt8;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes192_decrypt1;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes192_decrypt2;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes192_decrypt4;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes192_decrypt8;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes256_decrypt1;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes256_decrypt2;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes256_decrypt4;
    pub use aes_x86_aesni_aes_decrypt::aes_x86_aesni_aes256_decrypt8;

    pub use aes_x86_aesni_aes_inverse_key::aes_x86_aesni_aes128_inverse_key;
    pub use aes_x86_aesni_aes_inverse_key::aes_x86_aesni_aes192_inverse_key;
    pub use aes_x86_aesni_aes_inverse_key::aes_x86_aesni_aes256_inverse_key;

    pub use aes_x86_aesni_aes_expand_key::aes_x86_aesni_aes128_expand_key;
    pub use aes_x86_aesni_aes_expand_key::aes_x86_aesni_aes192_expand_key;
    pub use aes_x86_aesni_aes_expand_key::aes_x86_aesni_aes256_expand_key;
  }
}

cfg_if! {
  if #[cfg(any(target_arch = "arm", target_arch = "aarc64", doc))] {
    mod aes_arm_aes_aes_encrypt;
    mod aes_arm_aes_aes_decrypt;
    // mod aes_arm_aes_aes_inverse_key;
    // mod aes_arm_aes_aes_expand_key;

    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes128_encrypt1;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes128_encrypt2;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes128_encrypt4;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes128_encrypt8;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes192_encrypt1;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes192_encrypt2;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes192_encrypt4;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes192_encrypt8;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes256_encrypt1;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes256_encrypt2;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes256_encrypt4;
    pub use aes_arm_aes_aes_encrypt::aes_arm_aes_aes256_encrypt8;

    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes128_decrypt1;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes128_decrypt2;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes128_decrypt4;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes128_decrypt8;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes192_decrypt1;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes192_decrypt2;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes192_decrypt4;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes192_decrypt8;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes256_decrypt1;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes256_decrypt2;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes256_decrypt4;
    pub use aes_arm_aes_aes_decrypt::aes_arm_aes_aes256_decrypt8;

    // pub use aes_arm_aes_aes_inverse_key::aes_arm_aes_aes128_inverse_key;
    // pub use aes_arm_aes_aes_inverse_key::aes_arm_aes_aes192_inverse_key;
    // pub use aes_arm_aes_aes_inverse_key::aes_arm_aes_aes256_inverse_key;

    // pub use aes_arm_aes_aes_expand_key::aes_arm_aes_aes128_expand_key;
    // pub use aes_arm_aes_aes_expand_key::aes_arm_aes_aes192_expand_key;
    // pub use aes_arm_aes_aes_expand_key::aes_arm_aes_aes256_expand_key;
  }
}
