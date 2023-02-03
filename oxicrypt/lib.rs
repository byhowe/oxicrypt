#![no_std]
// #![deny(incomplete_features)]
#![feature(adt_const_params)]
#![feature(box_syntax)]
#![feature(const_maybe_uninit_assume_init)]
#![feature(const_mut_refs)]
#![feature(const_trait_impl)]
#![feature(doc_cfg)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![feature(stdsimd)]
#![feature(slice_as_chunks)]
#![cfg_attr(feature = "alloc", feature(new_uninit))]
#![allow(clippy::identity_op)]
#![allow(clippy::zero_prefixed_literal)]

#[cfg(any(feature = "alloc", doc))]
extern crate alloc;
#[cfg(any(feature = "std", doc))]
extern crate std;

pub mod aes;
pub mod digest;
// pub mod hkdf;
// pub mod hmac;
pub mod md5;
pub mod merkle_damgard;
pub mod sha;

#[cfg(test)] pub(crate) mod test_vectors;
