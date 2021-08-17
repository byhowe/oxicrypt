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

static mut GLOBAL_IMPL: Implementation = Implementation::new();

/// Tweak certain aspects of the library.
pub enum Control {}

impl Control
{
  /// Set the global implementation details.
  ///
  /// The globa implementation variable is used when using functions that do not accept an
  /// implementation variable or when using functions from traits (e.g. `std::io::Write`).
  ///
  /// # Safety
  ///
  /// Global implementation is stored in a mutable static variable that is **not** behind a mutex
  /// guard. Although it should not be a problem, it is still better to call this function before
  /// using any more of the library's functions (e.g. in `fn main() {}`).
  pub fn set_global_implementation(implementation: Implementation)
  {
    unsafe { GLOBAL_IMPL = implementation }
  }

  /// Get the global implementation variable.
  pub fn get_global_implementation() -> Implementation
  {
    unsafe { GLOBAL_IMPL }
  }

  /// Get a mutable reference to the global implementation variable.
  pub fn get_global_implementation_mut() -> &'static mut Implementation {
    unsafe { &mut GLOBAL_IMPL }
  }
}
