//! # The OxiCrypt Rust Library
//!
//! OxiCrypt is a cryptography library written mainly in Rust.
#![feature(new_uninit)]
#![feature(maybe_uninit_ref)]
#![feature(num_as_ne_bytes)]

pub mod aes;
pub mod sha;

#[cfg(test)]
mod tests;
