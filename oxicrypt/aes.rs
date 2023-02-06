//! High level AES API.

use core::mem::MaybeUninit;

use oxicrypt_core::*;
use Variant::*;

use crate::runtime::Feature;

mod sealed
{
    pub trait Sealed {}
}
use sealed::Sealed;

/// Specifies the number of bits (e.g 128, 192, 256) used by the AES algorithm.
pub struct Bits<const BITS: usize>;

impl<const BITS: usize> Bits<BITS>
{
    pub const fn variant() -> Variant
    {
        match BITS {
            | 128 => Variant::Aes128,
            | 192 => Variant::Aes192,
            | 256 => Variant::Aes256,

            // does not matter what this is since it is not a supported bit count.
            | _ => Variant::Aes128,
        }
    }
}

/// Statically guarantees that the number of bits is marked as supported.
///
/// This trait is *sealed*: the list of implementors below is total.
pub trait SupportedBits: Sealed {}

impl<const BITS: usize> Sealed for Bits<BITS> {}

impl SupportedBits for Bits<128> {}
impl SupportedBits for Bits<192> {}
impl SupportedBits for Bits<256> {}

/// AES comes in three variants. This enum is used to represent which one to
/// use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant
{
    Aes128,
    Aes192,
    Aes256,
}

impl Variant
{
    /// Length of the key.
    pub const fn key_len(self) -> usize
    {
        match self {
            | Aes128 => 16,
            | Aes192 => 24,
            | Aes256 => 32,
        }
    }

    /// Length of the key schedule.
    pub const fn key_sched_len(self) -> usize
    {
        match self {
            | Aes128 => 176,
            | Aes192 => 208,
            | Aes256 => 240,
        }
    }

    /// Number of rounds.
    pub const fn rounds(self) -> usize
    {
        match self {
            | Aes128 => 10,
            | Aes192 => 12,
            | Aes256 => 14,
        }
    }
}

/// Expanded key to use with AES.
///
/// # Note
///
/// AES uses different key schedules when encrypting or decrypting. If you
/// created a key schedule using either one of `set_encrypt_key` functions, you
/// cannot use the same key schedule for decrypting the data. This type does not
/// keep track of wheter it was created for encryption or decryption, so you
/// must be careful when using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<const BITS: usize>
where
    [(); Bits::<BITS>::variant().key_sched_len()]:,
    Bits<BITS>: SupportedBits,
{
    k: [u8; Bits::<BITS>::variant().key_sched_len()],
}

/// AES-128 key schedule.
pub type Key128 = Key<128>;
/// AES-192 key schedule.
pub type Key192 = Key<192>;
/// AES-256 key schedule.
pub type Key256 = Key<256>;

impl<const BITS: usize> Key<BITS>
where
    [(); Bits::<BITS>::variant().key_sched_len()]:,
    Bits<BITS>: SupportedBits,
{
    /// AES block size in bytes.
    pub const BLOCK_LEN: usize = 16;
    /// Key size in bytes.
    pub const KEY_LEN: usize = Self::VARIANT.key_len();
    /// Inner key schedule size in bytes.
    pub const KEY_SCHEDULE_LEN: usize = Self::VARIANT.key_sched_len();
    /// Number of rounds.
    pub const ROUNDS: usize = Self::VARIANT.rounds();
    /// AES variant.
    const VARIANT: Variant = Bits::<BITS>::variant();

    /// Returns the inner key schedule as a byte slice.
    pub const fn as_bytes(&self) -> &[u8] { &self.k }

    /// Returns a pointer to the inner key schedule.
    pub const fn as_ptr(&self) -> *const u8 { self.k.as_ptr() }

    /// Returns a mutable pointer to the inner key schedule.
    pub const fn as_mut_ptr(&mut self) -> *mut u8 { self.k.as_mut_ptr() }

    /// Creates a key schedule to use in encryption mode.
    ///
    /// Returns an [`Err`](`Result::Err`) when length of the `key` is not equal
    /// to 16 for AES128, 24 for AES192, 32 for AES256.
    pub fn with_encrypt_key(key: &[u8]) -> Result<Self, LenError>
    {
        if key.len() != Self::KEY_LEN {
            return Err(LenError {
                field:    "key",
                expected: Self::KEY_LEN,
                got:      key.len(),
            });
        }
        let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe {
            key_schedule
                .assume_init_mut()
                .set_encrypt_key_unchecked(key)
        };
        Ok(unsafe { key_schedule.assume_init() })
    }

    /// Creates a key schedule to use in encryption mode.
    ///
    /// # Safety
    ///
    /// * Length of `key` must be equal to 16 for AES128, 24 for AES192, 32 for
    ///   AES256.
    pub unsafe fn with_encrypt_key_unchecked(key: &[u8]) -> Result<Self, LenError>
    {
        let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
        key_schedule
            .assume_init_mut()
            .set_encrypt_key_unchecked(key);
        Ok(key_schedule.assume_init())
    }

    /// Creates a key schedule to use in decryption mode.
    ///
    /// Returns an [`Err`](`Result::Err`) when length of the `key` is not equal
    /// to 16 for AES128, 24 for AES192, 32 for AES256.
    pub fn with_decrypt_key(key: &[u8]) -> Result<Self, LenError>
    {
        if key.len() != Self::KEY_LEN {
            return Err(LenError {
                field:    "key",
                expected: Self::KEY_LEN,
                got:      key.len(),
            });
        }
        let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe {
            key_schedule
                .assume_init_mut()
                .set_decrypt_key_unchecked(key)
        };
        Ok(unsafe { key_schedule.assume_init() })
    }

    /// Creates a key schedule to use in decryption mode.
    ///
    /// # Safety
    ///
    /// * Length of the `key` must be equal to 16 for AES128, 24 for AES192, 32
    ///   for AES256.
    pub unsafe fn with_decrypt_key_unchecked(key: &[u8]) -> Result<Self, LenError>
    {
        let mut key_schedule: MaybeUninit<Self> = MaybeUninit::uninit();
        key_schedule
            .assume_init_mut()
            .set_decrypt_key_unchecked(key);
        Ok(key_schedule.assume_init())
    }

    /// Sets the encryption key.
    ///
    /// Note that the previous value stored in the key schedule is discarded.
    pub fn set_encrypt_key(&mut self, key: &[u8]) -> Result<(), LenError>
    {
        if key.len() != Self::KEY_LEN {
            return Err(LenError {
                field:    "key",
                expected: Self::KEY_LEN,
                got:      key.len(),
            });
        }
        unsafe { self.set_encrypt_key_unchecked(key) };
        Ok(())
    }

    /// Sets the decryption key.
    ///
    /// Note that the previous value stored in the key schedule is discarded.
    pub fn set_decrypt_key(&mut self, key: &[u8]) -> Result<(), LenError>
    {
        if key.len() != Self::KEY_LEN {
            return Err(LenError {
                field:    "key",
                expected: Self::KEY_LEN,
                got:      key.len(),
            });
        }
        unsafe { self.set_decrypt_key_unchecked(key) };
        Ok(())
    }

    /// Sets the encryption key.
    ///
    /// Note that the previous value stored in the key schedule is discarded.
    ///
    /// # Safety
    ///
    /// * Length of the `key` must be equal to 16 for AES128, 24 for AES192, 32
    ///   for AES256.
    pub unsafe fn set_encrypt_key_unchecked(&mut self, key: &[u8])
    {
        if Feature::Aesni.is_available() {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            match Self::VARIANT {
                | Aes128 => unsafe {
                    aes_x86_aesni_aes128_expand_key(key.as_ptr(), self.as_mut_ptr())
                },
                | Aes192 => unsafe {
                    aes_x86_aesni_aes192_expand_key(key.as_ptr(), self.as_mut_ptr())
                },
                | Aes256 => unsafe {
                    aes_x86_aesni_aes256_expand_key(key.as_ptr(), self.as_mut_ptr())
                },
            }
        } else {
            match Self::VARIANT {
                | Aes128 => unsafe { aes_lut_aes128_expand_key(key.as_ptr(), self.as_mut_ptr()) },
                | Aes192 => unsafe { aes_lut_aes192_expand_key(key.as_ptr(), self.as_mut_ptr()) },
                | Aes256 => unsafe { aes_lut_aes256_expand_key(key.as_ptr(), self.as_mut_ptr()) },
            }
        }
    }

    /// Sets the decryption key.
    ///
    /// Note that the previous value stored in the key schedule is discarded.
    ///
    /// # Safety
    ///
    /// * Length of the `key` must be equal to 16 for AES128, 24 for AES192, 32
    ///   for AES256.
    pub unsafe fn set_decrypt_key_unchecked(&mut self, key: &[u8])
    {
        self.set_encrypt_key_unchecked(key);
        self.inverse_key();
    }

    /// Converts an encryption key into a decryption key.
    ///
    /// Note that only encryption key can be converted into decryption key. If
    /// you try to run this function on a decryption key, the result is not
    /// guaranteed to be a valid encryption key.
    ///
    /// # Examples
    ///
    /// Encryption key -> Decryption key OK!
    /// ```
    /// # use oxicrypt::aes::*;
    /// let key: Vec<u8> = (0u8..Key128::KEY_LEN as u8).collect();
    /// let keysched_r = Key128::with_decrypt_key(&key).unwrap();
    /// let mut keysched_l = Key128::with_encrypt_key(&key).unwrap();
    /// keysched_l.inverse_key();
    /// assert_eq!(keysched_l, keysched_r);
    /// ```
    ///
    /// Decryption key -> Encryption key NOT OK!
    /// ```should_panic
    /// # use oxicrypt::aes::*;
    /// let key: Vec<u8> = (0u8..Key128::KEY_LEN as u8).collect();
    /// let keysched_r = Key128::with_encrypt_key(&key).unwrap();
    /// let mut keysched_l = Key128::with_decrypt_key(&key).unwrap();
    /// keysched_l.inverse_key();
    /// assert_eq!(keysched_l, keysched_r);
    /// ```
    pub fn inverse_key(&mut self)
    {
        if Feature::Aesni.is_available() {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            match Self::VARIANT {
                | Aes128 => unsafe { aes_x86_aesni_aes128_inverse_key(self.as_mut_ptr()) },
                | Aes192 => unsafe { aes_x86_aesni_aes192_inverse_key(self.as_mut_ptr()) },
                | Aes256 => unsafe { aes_x86_aesni_aes256_inverse_key(self.as_mut_ptr()) },
            }
        } else {
            match Self::VARIANT {
                | Aes128 => unsafe { aes_lut_aes128_inverse_key(self.as_mut_ptr()) },
                | Aes192 => unsafe { aes_lut_aes192_inverse_key(self.as_mut_ptr()) },
                | Aes256 => unsafe { aes_lut_aes256_inverse_key(self.as_mut_ptr()) },
            }
        }
    }

    /// Encrypts the given block in-place.
    ///
    /// Returns an [`Err`](`Result::Err`) when the length of `block` is not a
    /// multiple of 16.
    pub fn encrypt(&self, block: &mut [u8]) -> Result<(), LenError>
    {
        if block.len() % 16 != 0 {
            return Err(LenError {
                field:    "block",
                expected: block.len() / 16,
                got:      block.len(),
            });
        }
        unsafe { self.encrypt_unchecked(block) };
        Ok(())
    }

    /// Decrypts the given block in-place.
    ///
    /// Returns an [`Err`](`Result::Err`) when the length of `block` is not a
    /// multiple of 16.
    pub fn decrypt(&self, block: &mut [u8]) -> Result<(), LenError>
    {
        if block.len() % 16 != 0 {
            return Err(LenError {
                field:    "block",
                expected: block.len() / 16,
                got:      block.len(),
            });
        }
        unsafe { self.decrypt_unchecked(block) };
        Ok(())
    }

    /// Encrypts the given block in-place.
    ///
    /// # Safety
    ///
    /// * Length of `block` must be a multiple of 16.
    pub unsafe fn encrypt_unchecked(&self, mut block: &mut [u8])
    {
        if Feature::Aesni.is_available() {
            while !block.is_empty() {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                match block.len() / 16 {
                    | n if n >= 8 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_encrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_encrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_encrypt8(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[8 * 16..];
                    },
                    | n if n >= 4 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_encrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_encrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_encrypt4(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[4 * 16..];
                    },
                    | n if n >= 2 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_encrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_encrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_encrypt2(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[2 * 16..];
                    },
                    | _ => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[1 * 16..];
                    },
                }
            }
        } else if Feature::ArmAes.is_available() {
            while !block.is_empty() {
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                match block.len() / 16 {
                    | n if n >= 8 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_encrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_encrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_encrypt8(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[8 * 16..];
                    },
                    | n if n >= 4 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_encrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_encrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_encrypt4(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[4 * 16..];
                    },
                    | n if n >= 2 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_encrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_encrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_encrypt2(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[2 * 16..];
                    },
                    | _ => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[1 * 16..];
                    },
                }
            }
        } else {
            for block in block.as_chunks_unchecked_mut::<16>() {
                match Self::VARIANT {
                    | Aes128 => aes_lut_aes128_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                    | Aes192 => aes_lut_aes192_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                    | Aes256 => aes_lut_aes256_encrypt1(block.as_mut_ptr(), self.as_ptr()),
                }
            }
        }
    }

    /// Decrypts the given block in-place.
    ///
    /// # Safety
    ///
    /// * Length of `block` must be a multiple of 16.
    pub unsafe fn decrypt_unchecked(&self, mut block: &mut [u8])
    {
        if Feature::Aesni.is_available() {
            while !block.is_empty() {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                match block.len() / 16 {
                    | n if n >= 8 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_decrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_decrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_decrypt8(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[8 * 16..];
                    },
                    | n if n >= 4 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_decrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_decrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_decrypt4(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[4 * 16..];
                    },
                    | n if n >= 2 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_decrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_decrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_decrypt2(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[2 * 16..];
                    },
                    | _ => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_x86_aesni_aes128_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_x86_aesni_aes192_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_x86_aesni_aes256_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[1 * 16..];
                    },
                }
            }
        } else if Feature::ArmAes.is_available() {
            while !block.is_empty() {
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                match block.len() / 16 {
                    | n if n >= 8 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_decrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_decrypt8(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_decrypt8(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[8 * 16..];
                    },
                    | n if n >= 4 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_decrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_decrypt4(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_decrypt4(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[4 * 16..];
                    },
                    | n if n >= 2 => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_decrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_decrypt2(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_decrypt2(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[2 * 16..];
                    },
                    | _ => {
                        match Self::VARIANT {
                            | Aes128 =>
                                aes_arm_aes_aes128_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes192 =>
                                aes_arm_aes_aes192_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                            | Aes256 =>
                                aes_arm_aes_aes256_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                        }
                        block = &mut block[1 * 16..];
                    },
                }
            }
        } else {
            for block in block.as_chunks_unchecked_mut::<16>() {
                match Self::VARIANT {
                    | Aes128 => aes_lut_aes128_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                    | Aes192 => aes_lut_aes192_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                    | Aes256 => aes_lut_aes256_decrypt1(block.as_mut_ptr(), self.as_ptr()),
                }
            }
        }
    }
}

impl<const BITS: usize> AsRef<[u8]> for Key<BITS>
where
    [(); Bits::<BITS>::variant().key_sched_len()]:,
    Bits<BITS>: SupportedBits,
{
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

/// Error type for when the input length is not quite right.
#[derive(Clone, Copy, Debug)]
pub struct LenError
{
    field:    &'static str,
    expected: usize,
    got:      usize,
}

impl LenError
{
    pub const fn field(&self) -> &str { self.field }

    pub const fn expected(&self) -> usize { self.expected }

    pub const fn got(&self) -> usize { self.got }
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
