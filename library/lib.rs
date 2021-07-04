#![no_std]
#![allow(incomplete_features)]
#![feature(doc_cfg)]
#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(const_fn_fn_ptr_basics)]
#![feature(const_mut_refs)]
#![feature(const_ptr_offset)]

#[cfg(any(feature = "std", doc))]
extern crate std;

#[cfg_attr(c, panic_handler)]
#[cfg(c)]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> !
{
  loop {}
}

pub mod crypto;

pub mod aes;

#[cfg(test)]
pub(crate) mod test_vectors;
