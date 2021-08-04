#![no_std]
#![deny(incomplete_features)]
#![feature(doc_cfg)]
#![feature(stmt_expr_attributes)]
#![feature(const_fn_fn_ptr_basics)]
#![feature(const_unreachable_unchecked)]
#![feature(const_mut_refs)]
#![feature(const_ptr_offset)]
#![feature(const_maybe_uninit_assume_init)]
#![feature(const_raw_ptr_deref)]
#![feature(const_fn_trait_bound)]
#![cfg_attr(feature = "alloc", feature(new_uninit))]

#[cfg(any(feature = "alloc", doc))]
extern crate alloc;
#[cfg(any(feature = "std", doc))]
extern crate std;

pub mod hazmat;

#[doc(inline)]
pub use hazmat::Implementation;

pub mod aes;
pub mod digest;
pub mod hkdf;
pub mod hmac;
pub mod sha;

#[cfg(test)]
pub(crate) mod test_vectors;
