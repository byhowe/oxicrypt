#![no_std]
#![feature(doc_cfg)]

pub mod hwfeatures;

pub mod aes;
pub mod sha;

#[cfg(test)]
pub(crate) mod test_vectors;
