#![no_std]
#![allow(incomplete_features)]
#![feature(doc_cfg)]
#![feature(const_generics)]
#![feature(const_fn_fn_ptr_basics)]

pub mod aes;
pub mod sha;

#[cfg(test)]
pub(crate) mod test_vectors;
