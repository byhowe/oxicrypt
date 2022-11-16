#![no_std]
// #![deny(incomplete_features)]
#![feature(adt_const_params)]
#![feature(box_syntax)]
#![feature(const_fn_fn_ptr_basics)]
#![feature(const_fn_trait_bound)]
#![feature(const_maybe_uninit_assume_init)]
#![feature(const_mut_refs)]
#![feature(const_ptr_offset)]
#![feature(const_trait_impl)]
#![feature(doc_cfg)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![cfg_attr(feature = "alloc", feature(new_uninit))]

#[cfg(any(feature = "alloc", doc))]
extern crate alloc;
#[cfg(any(feature = "std", doc))]
extern crate std;

// pub mod hazmat;

// pub mod aes;
// pub mod digest;
// pub mod hkdf;
// pub mod hmac;
// pub mod sha;

#[cfg(test)]
pub(crate) mod test_vectors;
