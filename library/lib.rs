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
  pub fn get_global_implementation_mut() -> &'static mut Implementation
  {
    unsafe { &mut GLOBAL_IMPL }
  }
}

/// A structure repesenting available hardware features.
///
/// # Bits
///
/// `1 << 0` - AES with hardware acceleration (e.g. AES-NI on x86)
#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Implementation(u64);

impl Implementation
{
  /// Bits for AES with hardware acceleration.
  pub const AES: Self = Self(1 << 0);

  /// Implementation with all features disabled.
  pub const fn new() -> Self
  {
    Self(0)
  }

  /// Fastest implementation based on compile-time information.
  ///
  /// This will generally return the same thing as [`new`](`Self::new`) as it is generic accross
  /// all platforms. If compiled using `RUSTFLAGS='-C target-feature=+<feature>'` or a certain
  /// feature is known to be available during compilation, then it enables that feature.
  pub const fn fastest() -> Self
  {
    #[allow(unused_mut)]
    let mut i = Self::new();

    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
    i.enable(Self::AES);

    i
  }

  /// Fastest implementation based on runtime information.
  pub fn fastest_rt() -> Self
  {
    let mut i = Self::fastest();

    if Self::is_available(Self::AES) {
      i.enable(Self::AES);
    }

    i
  }

  /// Check if an implementation detail is supported by the CPU or the host platform.
  pub fn is_available(bits: Self) -> bool
  {
    if bits.is_present(Self::AES) && cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
      std_detect::is_x86_feature_detected!("aes")
    } else {
      false
    }
  }

  /// Checks whether or not given bits are set.
  ///
  /// Note that this is a simple bitwise-and operation under the hood. If you want to know if a
  /// feature is supported by the host platform use [`is_available`](`Self::is_available`) instead.
  pub const fn is_present(self, bits: Self) -> bool
  {
    self.0 & bits.0 != 0
  }

  /// Enables given bits.
  ///
  /// Note that this is a simple bitwise-or operation under the hood.
  pub const fn enable(&mut self, bits: Self) -> &mut Self
  {
    self.0 |= bits.0;
    self
  }
}
