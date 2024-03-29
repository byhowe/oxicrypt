#![no_std]
#![feature(new_uninit)]

extern crate alloc;

pub mod aes;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod aes_arm;
pub mod aes_lut;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod aesni;
pub mod digest;
pub mod hmac;
pub mod md_compress;
