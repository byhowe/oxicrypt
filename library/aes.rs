//! High level AES API.

use core::mem::MaybeUninit;

use crate::hazmat::aes;
use crate::hazmat::aes::Variant;
use crate::hazmat::Implementation;

/// Expanded key to use with AES.
///
/// # Safety
///
/// It is undefined behavior to specify `N` value other than `176`, `208` or `240`.
///
/// # Note
///
/// AES uses different key schedules when encrypting or decrypting. If you created a key schedule
/// using either one of `set_encrypt_key` functions, you cannot use the same key schedule for
/// decrypting data. This type does not keep track of wheter it was created for encryption or
/// decryption, so you must be careful when using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Key<const N: usize>
{
  k: [u8; N],
}

/// AES-128 key schedule.
pub type Key128 = Key<176>;
/// AES-192 key schedule.
pub type Key192 = Key<208>;
/// AES-256 key schedule.
pub type Key256 = Key<240>;

impl<const N: usize> Key<N>
{
  /// AES block size in bytes.
  pub const BLOCK_LEN: usize = 16;
  /// Key size in bytes.
  pub const KEY_LEN: usize = Variant::key_len(Self::V);
  /// Inner key schedule size in bytes.
  pub const KEY_SCHEDULE_LEN: usize = N;
  /// Number of rounds.
  pub const ROUNDS: usize = Variant::rounds(Self::V);
  const V: Variant = match N {
    | 176 => Variant::Aes128,
    | 208 => Variant::Aes192,
    | 240 => Variant::Aes256,
    | _ => unsafe { core::hint::unreachable_unchecked() },
  };

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

  /// Creates a key schedule to use in encryption mode.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `key` is not equal to
  /// [`Variant::key_len(V)`](`Variant::key_len`).
  pub fn with_encrypt_key<K: AsRef<[u8]>>(implementation: Implementation, key: K) -> Result<Self, LenError>
  {
    let key = key.as_ref();
    if key.len() != Variant::key_len(Self::V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(Self::V),
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
    if key.len() != Variant::key_len(Self::V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(Self::V),
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
    if key.len() != Variant::key_len(Self::V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(Self::V),
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
    if key.len() != Variant::key_len(Self::V) {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(Self::V),
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
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr()),
      },
      | _ => match Self::V {
        | Variant::Aes128 => aes::lut::aes128_expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr()),
        | Variant::Aes192 => aes::lut::aes192_expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr()),
        | Variant::Aes256 => aes::lut::aes256_expand_key(key.as_ref().as_ptr(), self.k.as_mut_ptr()),
      },
    }
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
  /// # use oxicrypt::Implementation;
  /// let key: Vec<u8> = (0u8 .. Variant::key_len(Variant::Aes128) as u8).collect();
  /// let implementation = Implementation::fastest_rt();
  /// let keysched_r = Key128::with_decrypt_key(implementation, &key).unwrap();
  /// let mut keysched_l = Key128::with_encrypt_key(implementation, &key).unwrap();
  /// keysched_l.inverse_key(implementation);
  /// assert_eq!(keysched_l, keysched_r);
  /// ```
  ///
  /// Decryption key -> Encryption key NOT OK!
  /// ```should_panic
  /// # use oxicrypt::aes::*;
  /// # use oxicrypt::Implementation;
  /// let key: Vec<u8> = (0u8 .. Variant::key_len(Variant::Aes128) as u8).collect();
  /// let implementation = Implementation::fastest_rt();
  /// let keysched_r = Key128::with_encrypt_key(implementation, &key).unwrap();
  /// let mut keysched_l = Key128::with_decrypt_key(implementation, &key).unwrap();
  /// keysched_l.inverse_key(implementation);
  /// assert_eq!(keysched_l, keysched_r);
  /// ```
  pub fn inverse_key(&mut self, implementation: Implementation)
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => unsafe { aes::aesni::aes128_inverse_key(self.k.as_mut_ptr()) },
        | Variant::Aes192 => unsafe { aes::aesni::aes192_inverse_key(self.k.as_mut_ptr()) },
        | Variant::Aes256 => unsafe { aes::aesni::aes256_inverse_key(self.k.as_mut_ptr()) },
      },
      | _ => match Self::V {
        | Variant::Aes128 => unsafe { aes::lut::aes128_inverse_key(self.k.as_mut_ptr()) },
        | Variant::Aes192 => unsafe { aes::lut::aes192_inverse_key(self.k.as_mut_ptr()) },
        | Variant::Aes256 => unsafe { aes::lut::aes256_inverse_key(self.k.as_mut_ptr()) },
      },
    }
  }

  /// Encrypts a single 16 byte block in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `16`.
  pub fn encrypt1(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 16 {
      return Err(LenError {
        field: "block",
        expected: 16,
        got: block.len(),
      });
    }
    unsafe { self.encrypt1_unchecked(implementation, block) };
    Ok(())
  }

  /// Encrypts two 16 byte blocks in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `32`.
  pub fn encrypt2(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 32 {
      return Err(LenError {
        field: "block",
        expected: 32,
        got: block.len(),
      });
    }
    unsafe { self.encrypt2_unchecked(implementation, block) };
    Ok(())
  }

  /// Encrypts four 16 byte blocks in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `64`.
  pub fn encrypt4(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 64 {
      return Err(LenError {
        field: "block",
        expected: 64,
        got: block.len(),
      });
    }
    unsafe { self.encrypt4_unchecked(implementation, block) };
    Ok(())
  }

  /// Encrypts eight 16 byte blocks in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `128`.
  pub fn encrypt8(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 128 {
      return Err(LenError {
        field: "block",
        expected: 128,
        got: block.len(),
      });
    }
    unsafe { self.encrypt8_unchecked(implementation, block) };
    Ok(())
  }

  /// Decrypts a single 16 byte block in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `16`.
  pub fn decrypt1(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 16 {
      return Err(LenError {
        field: "block",
        expected: 16,
        got: block.len(),
      });
    }
    unsafe { self.decrypt1_unchecked(implementation, block) };
    Ok(())
  }

  /// Decrypts two 16 byte blocks in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `32`.
  pub fn decrypt2(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 32 {
      return Err(LenError {
        field: "block",
        expected: 32,
        got: block.len(),
      });
    }
    unsafe { self.decrypt2_unchecked(implementation, block) };
    Ok(())
  }

  /// Decrypts four 16 byte blocks in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `64`.
  pub fn decrypt4(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 64 {
      return Err(LenError {
        field: "block",
        expected: 64,
        got: block.len(),
      });
    }
    unsafe { self.decrypt4_unchecked(implementation, block) };
    Ok(())
  }

  /// Decrypts eight 16 byte blocks in-place.
  ///
  /// Returns an [`Err`](`Result::Err`) when length of `block` is not `128`.
  pub fn decrypt8(&self, implementation: Implementation, block: &mut [u8]) -> Result<(), LenError>
  {
    if block.len() != 128 {
      return Err(LenError {
        field: "block",
        expected: 128,
        got: block.len(),
      });
    }
    unsafe { self.decrypt8_unchecked(implementation, block) };
    Ok(())
  }

  /// Encrypts a single 16 byte block in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `16`.
  pub unsafe fn encrypt1_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_encrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_encrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_encrypt1(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => match Self::V {
        | Variant::Aes128 => aes::lut::aes128_encrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::lut::aes192_encrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::lut::aes256_encrypt1(block.as_mut_ptr(), self.as_ptr()),
      },
    }
  }

  /// Encrypts two 16 byte blocks in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `32`.
  pub unsafe fn encrypt2_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_encrypt2(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_encrypt2(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_encrypt2(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => {
        // TODO Is there a more performant way of doing this?
        self.encrypt1_unchecked(implementation, &mut block[0 .. 16]);
        self.encrypt1_unchecked(implementation, &mut block[16 .. 32]);
      }
    }
  }

  /// Encrypts four 16 byte blocks in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `64`.
  pub unsafe fn encrypt4_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_encrypt4(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_encrypt4(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_encrypt4(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => {
        // TODO Is there a more performant way of doing this?
        self.encrypt1_unchecked(implementation, &mut block[0 .. 16]);
        self.encrypt1_unchecked(implementation, &mut block[16 .. 32]);
        self.encrypt1_unchecked(implementation, &mut block[32 .. 48]);
        self.encrypt1_unchecked(implementation, &mut block[48 .. 64]);
      }
    }
  }

  /// Encrypts eight 16 byte blocks in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `128`.
  pub unsafe fn encrypt8_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_encrypt8(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_encrypt8(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_encrypt8(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => {
        // TODO Is there a more performant way of doing this?
        self.encrypt1_unchecked(implementation, &mut block[0 .. 16]);
        self.encrypt1_unchecked(implementation, &mut block[16 .. 32]);
        self.encrypt1_unchecked(implementation, &mut block[32 .. 48]);
        self.encrypt1_unchecked(implementation, &mut block[48 .. 64]);
        self.encrypt1_unchecked(implementation, &mut block[64 .. 80]);
        self.encrypt1_unchecked(implementation, &mut block[80 .. 96]);
        self.encrypt1_unchecked(implementation, &mut block[96 .. 112]);
        self.encrypt1_unchecked(implementation, &mut block[112 .. 128]);
      }
    }
  }

  /// Decrypts a single 16 byte block in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `16`.
  pub unsafe fn decrypt1_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_decrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_decrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_decrypt1(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => match Self::V {
        | Variant::Aes128 => aes::lut::aes128_decrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::lut::aes192_decrypt1(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::lut::aes256_decrypt1(block.as_mut_ptr(), self.as_ptr()),
      },
    }
  }

  /// Decrypts two 16 byte blocks in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `32`.
  pub unsafe fn decrypt2_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_decrypt2(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_decrypt2(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_decrypt2(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => {
        // TODO Is there a more performant way of doing this?
        self.decrypt1_unchecked(implementation, &mut block[0 .. 16]);
        self.decrypt1_unchecked(implementation, &mut block[16 .. 32]);
      }
    }
  }

  /// Decrypts four 16 byte blocks in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `64`.
  pub unsafe fn decrypt4_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_decrypt4(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_decrypt4(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_decrypt4(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => {
        // TODO Is there a more performant way of doing this?
        self.decrypt1_unchecked(implementation, &mut block[0 .. 16]);
        self.decrypt1_unchecked(implementation, &mut block[16 .. 32]);
        self.decrypt1_unchecked(implementation, &mut block[32 .. 48]);
        self.decrypt1_unchecked(implementation, &mut block[48 .. 64]);
      }
    }
  }

  /// Decrypts eight 16 byte blocks in-place.
  ///
  /// # Safety
  ///
  /// * Length of `block` must be `128`.
  pub unsafe fn decrypt8_unchecked(&self, implementation: Implementation, block: &mut [u8])
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match Self::V {
        | Variant::Aes128 => aes::aesni::aes128_decrypt8(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes192 => aes::aesni::aes192_decrypt8(block.as_mut_ptr(), self.as_ptr()),
        | Variant::Aes256 => aes::aesni::aes256_decrypt8(block.as_mut_ptr(), self.as_ptr()),
      },
      | _ => {
        // TODO Is there a more performant way of doing this?
        self.decrypt1_unchecked(implementation, &mut block[0 .. 16]);
        self.decrypt1_unchecked(implementation, &mut block[16 .. 32]);
        self.decrypt1_unchecked(implementation, &mut block[32 .. 48]);
        self.decrypt1_unchecked(implementation, &mut block[48 .. 64]);
        self.decrypt1_unchecked(implementation, &mut block[64 .. 80]);
        self.decrypt1_unchecked(implementation, &mut block[80 .. 96]);
        self.decrypt1_unchecked(implementation, &mut block[96 .. 112]);
        self.decrypt1_unchecked(implementation, &mut block[112 .. 128]);
      }
    }
  }
}

impl<const N: usize> AsRef<[u8]> for Key<N>
{
  fn as_ref(&self) -> &[u8]
  {
    self.as_bytes()
  }
}

/// Error type for when the input length is not quite right.
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
