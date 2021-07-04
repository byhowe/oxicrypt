#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aesni;
mod lut;

/// AES implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation
{
  /// Look-up table based implementation.
  ///
  /// This implementation is always available on all platforms.
  Lut,
  /// Hardware accelerated implementation.
  ///
  /// This implementation is only available on x86 based chips that have the AES feature.
  #[cfg(any(any(target_arch = "x86", target_arch = "x86_64"), doc))]
  #[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
  Aesni,
}

impl Implementation
{
  /// Fastest implementation based on compile-time information.
  ///
  /// This will generally return [`Lut`](`Self::Lut`) as it is the generic implementation that is
  /// available on all platforms. If compiled using `RUSTFLAGS='-C target-feature=+aes'` or certain
  /// feature is known to be available during compile-time, then this function will return the
  /// fastest implementation based on that.
  pub const fn fastest_implementation() -> Self
  {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86"), target_feature = "aes"))]
    return Self::Aesni;

    Self::Lut
  }

  /// Performs a runtime check for wether or not a certain implementation is available.
  pub fn is_available(self) -> bool
  {
    match self {
      | Implementation::Lut => true,
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => std_detect::is_x86_feature_detected!("aes"),
    }
  }
}

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

/// Core AES structure that provides all the necessary functions to implement a higher level API.
///
/// # Examples
///
/// ```
/// # use oxicrypt::crypto::aes::Aes;
/// # use oxicrypt::crypto::aes::Implementation;
/// # use oxicrypt::crypto::aes::Variant;
/// // AES-128 type that uses the fastest implementation that is known to be available during
/// // compilation.
/// type Aes128 = Aes<{ Variant::Aes128 }, { Implementation::fastest_implementation() }>;
/// let key: Vec<u8> = (0u8 .. Aes128::key_len() as u8).collect();
/// let mut key_schedule = vec![0; Aes128::key_schedule_len()];
/// unsafe { Aes128::expand_key(key.as_ptr(), key_schedule.as_mut_ptr()) };
/// ```
pub struct Aes<const V: Variant, const I: Implementation>;

impl<const V: Variant, const I: Implementation> Aes<V, I>
{
  /// Same as [`Variant::rounds(V)`](`Variant::rounds`).
  pub const fn rounds() -> usize
  {
    Variant::rounds(V)
  }

  /// Same as [`Variant::key_len(V)`](`Variant::key_len`).
  pub const fn key_len() -> usize
  {
    Variant::key_len(V)
  }

  /// Same as [`Variant::key_schedule_len(V)`](`Variant::key_schedule_len`).
  pub const fn key_schedule_len() -> usize
  {
    Variant::key_schedule_len(V)
  }

  /// Expands the key into a larger key that can be used with AES in encryption mode.
  ///
  /// # Safety
  ///
  /// * `key` must be at least `Variant::key_len(V)` bytes.
  /// * `key_schedule` must be at least `Variant::key_schedule_len(V)` bytes.
  pub unsafe fn expand_key(key: *const u8, key_schedule: *mut u8)
  {
    match I {
      | Implementation::Lut => lut::aes_expand_key::<V>(key, key_schedule),
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => aesni::aes_expand_key::<V>(key, key_schedule),
    }
  }

  /// Inverses an encryption key to be used in decryption mode.
  ///
  /// # Safety
  ///
  /// * `key_schedule` must be at least `Variant::key_schedule_len(V)` bytes.
  pub unsafe fn inverse_key(key_schedule: *mut u8)
  {
    match I {
      | Implementation::Lut => lut::aes_inverse_key::<V>(key_schedule),
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => aesni::aes_inverse_key::<V>(key_schedule),
    }
  }

  /// Encrypts a single block.
  ///
  /// # Safety
  ///
  /// * `block` must be at least `16` bytes.
  /// * `key_schedule` must be at least `Variant::key_schedule_len(V)` bytes.
  pub unsafe fn encrypt1(block: *mut u8, key_schedule: *const u8)
  {
    match I {
      | Implementation::Lut => lut::aes_encrypt1::<V>(block, key_schedule),
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => aesni::aes_encrypt1::<V>(block, key_schedule),
    }
  }

  /// Decrypts a single block.
  ///
  /// # Safety
  ///
  /// * `block` must be at least `16` bytes.
  /// * `key_schedule` must be at least `Variant::key_schedule_len(V)` bytes.
  pub unsafe fn decrypt1(block: *mut u8, key_schedule: *const u8)
  {
    match I {
      | Implementation::Lut => lut::aes_decrypt1::<V>(block, key_schedule),
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => aesni::aes_decrypt1::<V>(block, key_schedule),
    }
  }
}
