//! Low level cryptography primitives.

/// A structure repesenting available hardware features.
///
/// # Bits
///
/// `1 << 0` - AES with hardware acceleration
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

  pub fn is_available(bits: Self) -> bool
  {
    if bits.is_present(Self::AES) && cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
      std_detect::is_x86_feature_detected!("aes")
    } else {
      false
    }
  }

  pub const fn is_present(self, bits: Self) -> bool
  {
    self.0 & bits.0 != 0
  }

  pub const fn enable(&mut self, bits: Self)
  {
    self.0 |= bits.0;
  }
}

pub mod aes;
pub mod md5;
pub mod sha;
