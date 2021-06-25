//! # The OxiCrypt Rust Library
//!
//! OxiCrypt is a cryptography library written mainly in Rust.

#![no_std]
#![cfg_attr(feature = "alloc", feature(new_uninit))]
#![allow(incomplete_features)]
#![feature(doc_cfg)]
#![feature(const_generics)]
#![feature(const_evaluatable_checked)]

#[cfg(any(feature = "std", doc))]
extern crate std;
#[cfg(any(feature = "alloc", doc))]
extern crate alloc;

pub mod aes;
pub mod sha;

#[cfg(test)]
mod tests;
