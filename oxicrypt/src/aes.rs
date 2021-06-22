//! Advanced Encryption Standard (also known as Rijndael).

#[cfg(feature = "alloc")]
use core::mem::MaybeUninit;
#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;

use oxicrypt_core::aes::AES128;
use oxicrypt_core::aes::AES192;
use oxicrypt_core::aes::AES256;

macro_rules! impl_aes {
  (
    $algo_str:expr;
    struct $algo:ident;
    const KEY_LEN: usize = $keylen:expr;
    const KEY_SCHEDULE_LEN: usize = $keyschedlen:expr;
    static AES = $aes:ident;
  ) => {
    #[doc = concat!($algo_str, " algorithm.")]
    #[derive(Clone, Copy)]
    pub struct $algo
    {
      key_schedule: [u8; Self::KEY_SCHEDULE_LEN],
    }

    impl $algo
    {
      /// Block length. It is equal to `16` for [`Aes128`], [`Aes192`] and [`Aes256`].
      pub const BLOCK_LEN: usize = 16;
      /// Length of the key. It is equal to
      #[doc = concat!("`", stringify!($keylen), "`")]
      /// for
      #[doc = $algo_str]
      pub const KEY_LEN: usize = $keylen;
      /// Length of the key after expanding it. It is equal to
      #[doc = concat!("`", stringify!($keyschedlen), "`")]
      /// for
      #[doc = $algo_str]
      pub const KEY_SCHEDULE_LEN: usize = $keyschedlen;

      /// Creates a new instance of
      #[doc = $algo_str]
      /// on the stack.
      ///
      /// Length of `key` must be exactly
      #[doc = concat!("`", stringify!($keylen), "`.")]
      /// The given key is expanded into an encryption key. After creating an
      /// instance of AES using this method, context is automatically in encryption mode. To put it
      /// in decrpyion mode, see [`set_decrypt_key`](`Self::set_decrypt_key`) and
      /// [`inverse_key`](`Self::inverse_key`).
      ///
      /// If you are sure that the length of `key` is at least
      #[doc = concat!("`", stringify!($keylen), "`,")]
      /// there is an unsafe version, [`new_unchecked`](`Self::new_unchecked`) , which does not
      /// check for the length of `key`.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::aes::", stringify!($algo), ";")]
      #[doc = concat!("let key: Vec<u8> = (0..", stringify!($keylen), ").collect();")]
      #[doc = concat!("let mut ctx: ", stringify!($algo), " = ", stringify!($algo), "::new(&key).unwrap();")]
      /// ```
      pub fn new(key: &[u8]) -> Result<Self, LenError>
      {
        if key.len() != $keylen {
          return Err(LenError {
            field: "key",
            expected: $keylen,
            got: key.len(),
          });
        }
        let mut ctx = Self {
          key_schedule: [0; $keyschedlen],
        };
        unsafe { $aes.expand_key(key.as_ptr(), ctx.key_schedule.as_mut_ptr()) };
        Ok(ctx)
      }

      /// Creates a new instance of
      #[doc = $algo_str]
      /// on the stack.
      ///
      /// See the safe version, [`new`](`Self::new`), for more details.
      ///
      /// # Safety
      ///
      /// This function is unsafe, because it does not check for the length of `key` which must be
      /// at least
      #[doc = concat!("`", stringify!($keylen), "`.")]
      pub unsafe fn new_unchecked(key: &[u8]) -> Self
      {
        let mut ctx = Self {
          key_schedule: [0; $keyschedlen],
        };
        $aes.expand_key(key.as_ptr(), ctx.key_schedule.as_mut_ptr());
        ctx
      }

      /// Creates a new instance of
      #[doc = $algo_str]
      /// on the heap.
      ///
      /// Length of `key` must be exactly
      #[doc = concat!("`", stringify!($keylen), "`.")]
      /// The given key is expanded into an encryption key. After creating an
      /// instance of AES using this method, context is automatically in encryption mode. To put it
      /// in decrpyion mode, see [`set_decrypt_key`](`Self::set_decrypt_key`) and
      /// [`inverse_key`](`Self::inverse_key`).
      ///
      /// If you are sure that the length of `key` is at least
      #[doc = concat!("`", stringify!($keylen), "`,")]
      /// there is an unsafe version, [`new_boxed_unchecked`](`Self::new_boxed_unchecked`) , which
      /// does not check for the length of `key`.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::aes::", stringify!($algo), ";")]
      #[doc = concat!("let key: Vec<u8> = (0..", stringify!($keylen), ").collect();")]
      #[doc = concat!("let mut ctx: Box<", stringify!($algo), "> = ", stringify!($algo), "::new_boxed(&key).unwrap();")]
      /// ```
      #[cfg(any(feature = "alloc", doc))]
      #[doc(cfg(any(feature = "std", feature = "alloc")))]
      pub fn new_boxed(key: &[u8]) -> Result<Box<Self>, LenError>
      {
        if key.len() != $keylen {
          return Err(LenError {
            field: "key",
            expected: $keylen,
            got: key.len(),
          });
        }
        let mut ctx: Box<MaybeUninit<Self>> = Box::new_uninit();
        unsafe { $aes.expand_key(key.as_ptr(), ctx.assume_init_mut().key_schedule.as_mut_ptr()) };
        Ok(unsafe { ctx.assume_init() })
      }

      /// Creates a new instance of
      #[doc = $algo_str]
      /// on the heap.
      ///
      /// See the safe version, [`new_boxed`](`Self::new_boxed`), for more details.
      ///
      /// # Safety
      ///
      /// This function is unsafe, because it does not check for the length of `key` which must be
      /// at least
      #[doc = concat!("`", stringify!($keylen), "`.")]
      #[cfg(any(feature = "alloc", doc))]
      #[doc(cfg(any(feature = "std", feature = "alloc")))]
      pub unsafe fn new_boxed_unchecked(key: &[u8]) -> Box<Self>
      {
        let mut ctx: Box<MaybeUninit<Self>> = Box::new_uninit();
        $aes.expand_key(key.as_ptr(), ctx.assume_init_mut().key_schedule.as_mut_ptr());
        ctx.assume_init()
      }

      /// Puts the context into encryption mode. The previous key stored in the context is
      /// overwritten. Note that when a context is created using [`new`](`Self::new`) or
      /// [`new_boxed`](`Self::new_boxed`), the context is already in encryption mode, so no need
      /// to call this function right after creating it.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::aes::", stringify!($algo), ";")]
      #[doc = concat!("let key: Vec<u8> = (0..", stringify!($keylen), ").collect();")]
      #[doc = concat!("let mut ctx: ", stringify!($algo), " = ", stringify!($algo), "::new(&key).unwrap();")]
      /// // Put the context into decryption mode.
      /// ctx.inverse_key();
      /// // ...
      /// // Put the context back into encryption mode.
      /// ctx.set_encrypt_key(&key).unwrap();
      /// ```
      pub fn set_encrypt_key(&mut self, key: &[u8]) -> Result<(), LenError>
      {
        if key.len() != $keylen {
          return Err(LenError {
            field: "key",
            expected: $keylen,
            got: key.len(),
          });
        }
        unsafe { $aes.expand_key(key.as_ptr(), self.key_schedule.as_mut_ptr()) };
        Ok(())
      }

      pub fn set_decrypt_key(&mut self, key: &[u8]) -> Result<(), LenError>
      {
        if key.len() != $keylen {
          return Err(LenError {
            field: "key",
            expected: $keylen,
            got: key.len(),
          });
        }
        unsafe { $aes.expand_key(key.as_ptr(), self.key_schedule.as_mut_ptr()) };
        unsafe { $aes.inverse_key(self.key_schedule.as_mut_ptr()) };
        Ok(())
      }

      pub unsafe fn set_decrypt_key_unchecked(&mut self, key: &[u8])
      {
        $aes.expand_key(key.as_ptr(), self.key_schedule.as_mut_ptr());
        $aes.inverse_key(self.key_schedule.as_mut_ptr());
      }

      pub fn inverse_key(&mut self)
      {
        unsafe { $aes.inverse_key(self.key_schedule.as_mut_ptr()) };
      }

      pub fn encrypt_single(&self, block: &mut [u8]) -> Result<(), LenError>
      {
        if block.len() != 16 {
          return Err(LenError {
            field: "block",
            expected: 16,
            got: block.len(),
          });
        }
        unsafe { $aes.encrypt(block.as_mut_ptr(), self.key_schedule.as_ptr()) };
        Ok(())
      }

      pub unsafe fn encrypt_single_unchecked(&self, block: &mut [u8])
      {
        $aes.encrypt(block.as_mut_ptr(), self.key_schedule.as_ptr());
      }

      pub fn decrypt_single(&self, block: &mut [u8]) -> Result<(), LenError>
      {
        if block.len() != 16 {
          return Err(LenError {
            field: "block",
            expected: 16,
            got: block.len(),
          });
        }
        unsafe { $aes.decrypt(block.as_mut_ptr(), self.key_schedule.as_ptr()) };
        Ok(())
      }

      pub unsafe fn decrypt_single_unchecked(&self, block: &mut [u8])
      {
        $aes.decrypt(block.as_mut_ptr(), self.key_schedule.as_ptr());
      }
    }
  };
}

impl_aes! {
  "AES-128";
  struct Aes128;
  const KEY_LEN: usize = 16;
  const KEY_SCHEDULE_LEN: usize = 176;
  static AES = AES128;
}

impl_aes! {
  "AES-192";
  struct Aes192;
  const KEY_LEN: usize = 24;
  const KEY_SCHEDULE_LEN: usize = 208;
  static AES = AES192;
}

impl_aes! {
  "AES-256";
  struct Aes256;
  const KEY_LEN: usize = 32;
  const KEY_SCHEDULE_LEN: usize = 240;
  static AES = AES256;
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
