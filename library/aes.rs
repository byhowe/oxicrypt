use core::mem::MaybeUninit;

use crate::crypto::aes::Aes;
use crate::crypto::aes::Implementation;
#[doc(inline)]
pub use crate::crypto::aes::Variant;

/// Pointers to unsafe AES functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine<const V: Variant>
{
  expand_key: unsafe fn(*const u8, *mut u8),
  inverse_key: unsafe fn(*mut u8),
  encrypt1: unsafe fn(*mut u8, *const u8),
  decrypt1: unsafe fn(*mut u8, *const u8),
}

impl<const V: Variant> Engine<V>
{
  /// Returns the appropriate engine for a given implementation.
  ///
  /// # Safety
  ///
  /// Note that this function does not perform any kind of check for wheter a given
  /// implementation is available during runtime. If you try to use an engine with an
  /// implementation that is not available during runtime, it might result in an illegal
  /// instruction signal.
  pub const unsafe fn new(implementation: Implementation) -> Self
  {
    match implementation {
      | Implementation::Lut => Engine {
        expand_key: Aes::<V, { Implementation::Lut }>::expand_key,
        inverse_key: Aes::<V, { Implementation::Lut }>::inverse_key,
        encrypt1: Aes::<V, { Implementation::Lut }>::encrypt1,
        decrypt1: Aes::<V, { Implementation::Lut }>::decrypt1,
      },
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | Implementation::Aesni => Engine {
        expand_key: Aes::<V, { Implementation::Aesni }>::expand_key,
        inverse_key: Aes::<V, { Implementation::Aesni }>::inverse_key,
        encrypt1: Aes::<V, { Implementation::Aesni }>::encrypt1,
        decrypt1: Aes::<V, { Implementation::Aesni }>::decrypt1,
      },
    }
  }

  /// Returns the fastest engine that is available during runtime.
  pub fn fastest() -> Self
  {
    unsafe {
      #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
      {
        Self::new(Implementation::Lut)
      }

      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      if Implementation::is_available(Implementation::Aesni) {
        Self::new(Implementation::Aesni)
      } else {
        Self::new(Implementation::Lut)
      }
    }
  }
}

/// Expanded key to use with AES.
///
/// AES uses different key schedules when encrypting or decrypting. If you created a key schedule
/// using either one of `set_encrypt_key` functions, you cannot use the same key schedule for
/// decrypting data. This type does not keep track of wheter it was created for encryption or
/// decryption, so you must be careful when using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeySchedule<const V: Variant>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  k: [u8; Variant::key_schedule_len(V)],
}

impl<const V: Variant> KeySchedule<V>
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
  /// let engine = Engine::<{ Variant::Aes128 }>::fastest();
  /// let mut keysched = KeySchedule::<{ Variant::Aes128 }>::uninit();
  /// unsafe { keysched.assume_init_mut() }
  ///   .set_encrypt_key(&engine, &key)
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
  pub fn with_encrypt_key<K: AsRef<[u8]>>(engine: &Engine<V>, key: K) -> Result<Self, LenError>
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
    unsafe { key_schedule.assume_init_mut().set_encrypt_key_unchecked(engine, key) };
    Ok(unsafe { key_schedule.assume_init() })
  }

  /// Creates a key schedule to use in decryption mode.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `key` is not equal to
  /// [`Variant::key_len(V)`](`Variant::key_len`).
  pub fn with_decrypt_key<K: AsRef<[u8]>>(engine: &Engine<V>, key: K) -> Result<Self, LenError>
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
    unsafe { key_schedule.assume_init_mut().set_decrypt_key_unchecked(engine, key) };
    Ok(unsafe { key_schedule.assume_init() })
  }

  /// Creates a key schedule to use in encryption mode.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn with_encrypt_key_unchecked<K: AsRef<[u8]>>(engine: &Engine<V>, key: K) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
    key_schedule.assume_init_mut().set_encrypt_key_unchecked(engine, key);
    Ok(key_schedule.assume_init())
  }

  /// Creates a key schedule to use in decryption mode.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn with_decrypt_key_unchecked<K: AsRef<[u8]>>(engine: &Engine<V>, key: K) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
    key_schedule.assume_init_mut().set_decrypt_key_unchecked(engine, key);
    Ok(key_schedule.assume_init())
  }

  /// Sets encryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  pub fn set_encrypt_key<K: AsRef<[u8]>>(&mut self, engine: &Engine<V>, key: K) -> Result<(), LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.len(),
      });
    }
    unsafe { self.set_encrypt_key_unchecked(engine, key) };
    Ok(())
  }

  /// Sets decryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  pub fn set_decrypt_key<K: AsRef<[u8]>>(&mut self, engine: &Engine<V>, key: K) -> Result<(), LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.len(),
      });
    }
    unsafe { self.set_decrypt_key_unchecked(engine, key) };
    Ok(())
  }

  /// Sets encryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn set_encrypt_key_unchecked<K: AsRef<[u8]>>(&mut self, engine: &Engine<V>, key: K)
  {
    (engine.expand_key)(key.as_ref().as_ptr(), self.k.as_mut_ptr());
  }

  /// Sets decryption key.
  ///
  /// Note that the previous value stored in the key schedule is discarded.
  ///
  /// # Safety
  ///
  /// * Length of `key` must be equal to [`Variant::key_len(V)`](`Variant::key_len`).
  pub unsafe fn set_decrypt_key_unchecked<K: AsRef<[u8]>>(&mut self, engine: &Engine<V>, key: K)
  {
    self.set_encrypt_key_unchecked(engine, key);
    self.inverse_key(engine);
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
  /// let engine = Engine::<{ Variant::Aes128 }>::fastest();
  /// let keysched_r = KeySchedule::<{ Variant::Aes128 }>::with_decrypt_key(&engine, &key).unwrap();
  /// let mut keysched_l = KeySchedule::<{ Variant::Aes128 }>::with_encrypt_key(&engine, &key).unwrap();
  /// keysched_l.inverse_key(&engine);
  /// assert_eq!(keysched_l, keysched_r);
  /// ```
  ///
  /// Decryption key -> Encryption key NOT OK!
  /// ```should_panic
  /// # use oxicrypt::aes::*;
  /// let key: Vec<u8> = (0u8 .. Variant::key_len(Variant::Aes128) as u8).collect();
  /// let engine = Engine::<{ Variant::Aes128 }>::fastest();
  /// let keysched_r = KeySchedule::<{ Variant::Aes128 }>::with_encrypt_key(&engine, &key).unwrap();
  /// let mut keysched_l = KeySchedule::<{ Variant::Aes128 }>::with_decrypt_key(&engine, &key).unwrap();
  /// keysched_l.inverse_key(&engine);
  /// assert_eq!(keysched_l, keysched_r);
  /// ```
  pub fn inverse_key(&mut self, engine: &Engine<V>)
  {
    unsafe { (engine.inverse_key)(self.k.as_mut_ptr()) };
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

impl<const V: Variant> AsRef<[u8]> for KeySchedule<V>
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
  engine: &Engine<V>,
  block: &mut [u8],
  key_schedule: &KeySchedule<V>,
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
  unsafe { (engine.encrypt1)(block.as_mut_ptr(), key_schedule.as_ptr()) };
  Ok(())
}

/// Decrypts a single 16 byte block in-place.
///
/// Returns an [`Err`](`Result::Err`) when length of `block` is not `16`.
pub fn decrypt1<const V: Variant>(
  engine: &Engine<V>,
  block: &mut [u8],
  key_schedule: &KeySchedule<V>,
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
  unsafe { (engine.decrypt1)(block.as_mut_ptr(), key_schedule.as_ptr()) };
  Ok(())
}

/// Encrypts a single 16 byte block in-place.
///
/// # Safety
///
/// * Length of `key` must be `16`.
pub unsafe fn encrypt1_unchecked<const V: Variant>(engine: &Engine<V>, block: &mut [u8], key_schedule: &KeySchedule<V>)
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  (engine.encrypt1)(block.as_mut_ptr(), key_schedule.as_ptr());
}

/// Decrypts a single 16 byte block in-place.
///
/// # Safety
///
/// * Length of `key` must be `16`.
pub unsafe fn decrypt1_unchecked<const V: Variant>(engine: &Engine<V>, block: &mut [u8], key_schedule: &KeySchedule<V>)
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  (engine.decrypt1)(block.as_mut_ptr(), key_schedule.as_ptr());
}

#[derive(Clone, Copy, Debug)]
pub struct LenError
{
  field: &'static str,
  expected: usize,
  got: usize,
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
