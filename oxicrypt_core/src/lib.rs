//! # The Oxicrypt Core Library
//!
//! The Oxicrypt Core Library is a collection of low level cryptography
//! functions that can be used to build a cryptography library. It is the
//! foundation for the the Oxicrypt Cryptography Library which exposes a higher
//! level and a safer API that is built on top of `oxicrypt_core`. This
//! library should not be used on its own as it icludes unsafe functions.

#![no_std]
#![feature(doc_cfg)]
#![feature(const_mut_refs)]
#![feature(stdsimd)]
#![allow(clippy::identity_op)]
#![allow(clippy::zero_prefixed_literal)]

#[cfg(any(target_arch = "arm", target_arch = "aarch64", doc))]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub mod aes_arm;
pub mod aes_lut;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", doc))]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub mod aesni;
pub mod md_compress;
