//! # The Oxicrypt Core Library
//!
//! The Oxicrypt Core Library is a collection of low level cryptography
//! functions that can be used to build a cryptography library. It is the
//! foundation for the the Oxicrypt Cryptography Library which exposes a higher
//! level and a safer API that is built on top of `oxicrypt_core`. This
//! library should not be used on its own as it icludes unsafe functions.

#![no_std]
#![feature(doc_cfg)]
#![feature(generic_const_exprs)]
#![feature(const_mut_refs)]
#![allow(clippy::identity_op)]
#![allow(clippy::zero_prefixed_literal)]

use cfg_if::cfg_if;

mod aes_lut_aes_core;
mod md5_generic_md5_compress;
mod sha_generic_sha1_compress;
mod sha_generic_sha256_compress;
mod sha_generic_sha512_compress;

pub use aes_lut_aes_core::*;
pub use md5_generic_md5_compress::md5_generic_md5_compress;
pub use sha_generic_sha1_compress::sha_generic_sha1_compress;
pub use sha_generic_sha256_compress::sha_generic_sha256_compress;
pub use sha_generic_sha512_compress::sha_generic_sha512_compress;

cfg_if! {
  if #[cfg(any(target_arch = "x86", target_arch = "x86_64", doc))] {
    // full set of AES-NI powered aes functions
    mod aes_x86_aesni_aes_encrypt;
    mod aes_x86_aesni_aes_decrypt;
    mod aes_x86_aesni_aes_inverse_key;
    mod aes_x86_aesni_aes_expand_key;

    pub use aes_x86_aesni_aes_encrypt::*;
    pub use aes_x86_aesni_aes_decrypt::*;
    pub use aes_x86_aesni_aes_inverse_key::*;
    pub use aes_x86_aesni_aes_expand_key::*;
  }
}

cfg_if! {
  if #[cfg(any(target_arch = "arm", target_arch = "aarc64", doc))] {
    mod aes_arm_aes_aes_encrypt;
    mod aes_arm_aes_aes_decrypt;
    // mod aes_arm_aes_aes_inverse_key;
    // mod aes_arm_aes_aes_expand_key;

    pub use aes_arm_aes_aes_encrypt::*;
    pub use aes_arm_aes_aes_decrypt::*;
    // pub use aes_arm_aes_aes_inverse_key::*;
    // pub use aes_arm_aes_aes_expand_key::*;
  }
}
