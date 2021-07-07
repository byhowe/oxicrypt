//! High level AES API.

use core::mem::MaybeUninit;

#[doc(inline)]
pub use crate::crypto::aes::Implementation;
#[doc(inline)]
pub use crate::crypto::aes::Variant;
use crate::crypto::aes::Engine;

/// Expanded key to use with AES.
///
/// AES uses different key schedules when encrypting or decrypting. If you created a key schedule
/// using either one of `set_encrypt_key` functions, you cannot use the same key schedule for
/// decrypting data. This type does not keep track of wheter it was created for encryption or
/// decryption, so you must be careful when using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(c, repr(C))]
pub struct Key<const V: Variant>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  k: [u8; Variant::key_schedule_len(V)],
}

/// AES-128 key schedule.
pub type Key128 = Key<{ Variant::Aes128 }>;
/// AES-192 key schedule.
pub type Key192 = Key<{ Variant::Aes192 }>;
/// AES-256 key schedule.
pub type Key256 = Key<{ Variant::Aes256 }>;

impl<const V: Variant> Key<V>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  /// Uninitialized key schedule.
  ///
  /// # Examples
  ///
  /// ```
  /// # use oxicrypt::aes::*;
  /// let key: Vec<u8> = (0u8 .. Variant::key_len(Variant::Aes128) as u8).collect();
  /// let implementation = Implementation::fastest_rt();
  /// let mut keysched = Key::<{ Variant::Aes128 }>::uninit();
  /// unsafe { keysched.assume_init_mut() }
  ///   .set_encrypt_key(implementation, &key)
  ///   .unwrap();
  /// let keysched = unsafe { keysched.assume_init() };
  /// ```
  pub const fn uninit() -> MaybeUninit<Self>
  {
    MaybeUninit::uninit()
  }

  /// Creates a key schedule to use in encryption mode.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `key` is not equal to
  /// [`Variant::key_len(V)`](`Variant::key_len`).
  pub fn with_encrypt_key<K: AsRef<[u8]>>(implementation: Implementation, key: K) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.len(),
      });
    }
    let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe {
      key_schedule
        .assume_init_mut()
        .set_encrypt_key_unchecked(implementation, key)
    };
    Ok(unsafe { key_schedule.assume_init() })
  }

  /// Creates a key schedule to use in decryption mode.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `key` is not equal to
  /// [`Variant::key_len(V)`](`Variant::key_len`).
  pub fn with_decrypt_key<K: AsRef<[u8]>>(implementation: Implementation, key: K) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.len(),
      });
    }
    let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe {
      key_schedule
        .assume_init_mut()
        .set_decrypt_key_unchecked(implementation, key)
    };
    Ok(unsafe { key_schedule.assume_init() })
  }

  /// Creates a key schedule to use in encryption mode.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn with_encrypt_key_unchecked<K: AsRef<[u8]>>(
    implementation: Implementation,
    key: K,
  ) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
    key_schedule
      .assume_init_mut()
      .set_encrypt_key_unchecked(implementation, key);
    Ok(key_schedule.assume_init())
  }

  /// Creates a key schedule to use in decryption mode.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn with_decrypt_key_unchecked<K: AsRef<[u8]>>(
    implementation: Implementation,
    key: K,
  ) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
    key_schedule
      .assume_init_mut()
      .set_decrypt_key_unchecked(implementation, key);
    Ok(key_schedule.assume_init())
  }

  /// Sets encryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  pub fn set_encrypt_key<K: AsRef<[u8]>>(&mut self, implementation: Implementation, key: K) -> Result<(), LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.len(),
      });
    }
    unsafe { self.set_encrypt_key_unchecked(implementation, key) };
    Ok(())
  }

  /// Sets decryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  pub fn set_decrypt_key<K: AsRef<[u8]>>(&mut self, implementation: Implementation, key: K) -> Result<(), LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.len(),
      });
    }
    unsafe { self.set_decrypt_key_unchecked(implementation, key) };
    Ok(())
  }

  /// Sets encryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn set_encrypt_key_unchecked<K: AsRef<[u8]>>(&mut self, implementation: Implementation, key: K)
  {
    Engine::as_ref::<V>(implementation).expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr());
  }

  /// Sets decryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn set_decrypt_key_unchecked<K: AsRef<[u8]>>(&mut self, implementation: Implementation, key: K)
  {
    self.set_encrypt_key_unchecked(implementation, key);
    self.inverse_key(implementation);
  }

  /// Converts an encryption key into a decryption key.
  ///
  /// Note that only encryption key can be converted into decryption key. If you try to run this
  /// function on a decryption key, the result is not guaranteed to be a valid encryption key.
  ///
  /// # Examples
  ///
  /// Encryption key -> Decryption key OK!
  /// ```
  /// # use oxicrypt::aes::*;
  /// let key: Vec<u8> = (0u8 .. Variant::key_len(Variant::Aes128) as u8).collect();
  /// let implementation = Implementation::fastest_rt();
  /// let keysched_r = Key::<{ Variant::Aes128 }>::with_decrypt_key(implementation, &key).unwrap();
  /// let mut keysched_l = Key::<{ Variant::Aes128 }>::with_encrypt_key(implementation, &key).unwrap();
  /// keysched_l.inverse_key(implementation);
  /// assert_eq!(keysched_l, keysched_r);
  /// ```
  ///
  /// Decryption key -> Encryption key NOT OK!
  /// ```should_panic
  /// # use oxicrypt::aes::*;
  /// let key: Vec<u8> = (0u8 .. Variant::key_len(Variant::Aes128) as u8).collect();
  /// let implementation = Implementation::fastest_rt();
  /// let keysched_r = Key::<{ Variant::Aes128 }>::with_encrypt_key(implementation, &key).unwrap();
  /// let mut keysched_l = Key::<{ Variant::Aes128 }>::with_decrypt_key(implementation, &key).unwrap();
  /// keysched_l.inverse_key(implementation);
  /// assert_eq!(keysched_l, keysched_r);
  /// ```
  pub fn inverse_key(&mut self, implementation: Implementation)
  {
    unsafe { Engine::as_ref::<V>(implementation).inverse_key(self.k.as_mut_ptr()) };
  }

  /// Returns the byte slice.
  pub const fn as_bytes(&self) -> &[u8]
  {
    &self.k
  }

  /// Returns a pointer to the key schedule.
  pub const fn as_ptr(&self) -> *const u8
  {
    self.k.as_ptr()
  }

  /// Returns a mutable pointer to the key schedule.
  pub const fn as_mut_ptr(&mut self) -> *mut u8
  {
    self.k.as_mut_ptr()
  }
}

impl<const V: Variant> AsRef<[u8]> for Key<V>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  fn as_ref(&self) -> &[u8]
  {
    self.as_bytes()
  }
}

/// Encrypts a single 16 byte block in-place.
///
/// Returns an [`Err`](`Result::Err`) when length of `block` is not `16`.
pub fn encrypt1<const V: Variant>(
  implementation: Implementation,
  block: &mut [u8],
  key_schedule: &Key<V>,
) -> Result<(), LenError>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  if block.len() != 16 {
    return Err(LenError {
      field: "block",
      expected: 16,
      got: block.len(),
    });
  }
  unsafe { Engine::as_ref::<V>(implementation).encrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
  Ok(())
}

/// Decrypts a single 16 byte block in-place.
///
/// Returns an [`Err`](`Result::Err`) when length of `block` is not `16`.
pub fn decrypt1<const V: Variant>(
  implementation: Implementation,
  block: &mut [u8],
  key_schedule: &Key<V>,
) -> Result<(), LenError>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  if block.len() != 16 {
    return Err(LenError {
      field: "block",
      expected: 16,
      got: block.len(),
    });
  }
  unsafe { Engine::as_ref::<V>(implementation).decrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
  Ok(())
}

/// Encrypts a single 16 byte block in-place.
///
/// # Safety
///
/// * Length of `key` must be `16`.
pub unsafe fn encrypt1_unchecked<const V: Variant>(
  implementation: Implementation,
  block: &mut [u8],
  key_schedule: &Key<V>,
) where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  Engine::as_ref::<V>(implementation).encrypt1(block.as_mut_ptr(), key_schedule.as_ptr());
}

/// Decrypts a single 16 byte block in-place.
///
/// # Safety
///
/// * Length of `key` must be `16`.
pub unsafe fn decrypt1_unchecked<const V: Variant>(
  implementation: Implementation,
  block: &mut [u8],
  key_schedule: &Key<V>,
) where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  Engine::as_ref::<V>(implementation).decrypt1(block.as_mut_ptr(), key_schedule.as_ptr());
}

#[derive(Clone, Copy, Debug)]
pub struct LenError
{
  field: &'static str,
  expected: usize,
  got: usize,
}

impl LenError
{
  pub const fn field(&self) -> &str
  {
    self.field
  }

  pub const fn expected(&self) -> usize
  {
    self.expected
  }

  pub const fn got(&self) -> usize
  {
    self.got
  }
}

impl core::fmt::Display for LenError
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
  {
    write!(
      f,
      "Length of `{}` was expected to be {}, but got {} instead",
      self.field, self.expected, self.got
    )
  }
}

#[cfg(any(feature = "std", doc))]
#[doc(cfg(feature = "std"))]
impl std::error::Error for LenError {}
