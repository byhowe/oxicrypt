#![no_std]
#![allow(incomplete_features)]
#![feature(doc_cfg)]
#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(const_fn_fn_ptr_basics)]
#![feature(const_mut_refs)]
#![feature(const_ptr_offset)]
#![feature(const_fn_transmute)]
#![feature(const_maybe_uninit_assume_init)]
#![cfg_attr(feature = "alloc", feature(new_uninit))]

#[cfg(any(feature = "alloc", doc))]
extern crate alloc;
#[cfg(any(feature = "std", doc))]
extern crate std;

#[cfg(c)]
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> !
{
  loop {}
}

pub mod crypto;

pub mod aes;
pub mod sha;

#[cfg(c)]
pub mod c;

#[cfg(test)]
pub(crate) mod test_vectors;
