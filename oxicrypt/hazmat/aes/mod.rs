#[cfg(any(any(target_arch = "x86", target_arch = "x86_64"), doc))]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub mod aesni;
pub mod lut;

/// AES variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant
{
  /// AES-128
  Aes128,
  /// AES-192
  Aes192,
  /// AES-256
  Aes256,
}

impl Variant
{
  /// Number of rounds.
  ///
  /// * AES-128 - `10`
  /// * AES-192 - `12`
  /// * AES-256 - `14`
  pub const fn rounds(self) -> usize
  {
    match self {
      | Self::Aes128 => 10,
      | Self::Aes192 => 12,
      | Self::Aes256 => 14,
    }
  }

  /// Key length.
  ///
  /// * AES-128 - `16`
  /// * AES-192 - `24`
  /// * AES-256 - `32`
  pub const fn key_len(self) -> usize
  {
    match self {
      | Self::Aes128 => 16,
      | Self::Aes192 => 24,
      | Self::Aes256 => 32,
    }
  }

  /// Key schedule length.
  ///
  /// * AES-128 - `176`
  /// * AES-192 - `208`
  /// * AES-256 - `240`
  pub const fn key_schedule_len(self) -> usize
  {
    match self {
      | Self::Aes128 => 176,
      | Self::Aes192 => 208,
      | Self::Aes256 => 240,
    }
  }
}

impl core::fmt::Display for Variant
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
  {
    match *self {
      | Self::Aes128 => f.write_str("AES-128"),
      | Self::Aes192 => f.write_str("AES-192"),
      | Self::Aes256 => f.write_str("AES-256"),
    }
  }
}
