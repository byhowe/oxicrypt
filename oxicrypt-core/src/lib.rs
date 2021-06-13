// We use the dynamic hardware feature detection capabilities of the std library when running tests.
#![cfg_attr(not(test), no_std)]
#![feature(doc_cfg)]

pub mod aes;
pub mod sha;

#[cfg(test)]
pub(crate) mod test_vectors;
