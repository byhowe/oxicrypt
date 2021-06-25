//! Advanced Encryption Standard (also known as Rijndael).

use oxicrypt_core::aes::Control;
#[doc(inline)]
pub use oxicrypt_core::aes::Variant;

#[derive(Clone, Copy)]
pub struct Aes<const V: Variant>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  key_schedule: [u8; Variant::key_schedule_len(V)],
}

impl<const V: Variant> Default for Aes<V>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  fn default() -> Self
  {
    Self::new()
  }
}

impl<const V: Variant> Aes<V>
where
  [u8; Variant::key_schedule_len(V)]: Sized,
{
  pub const BLOCK_LEN: usize = 16;
  pub const KEY_LEN: usize = Variant::key_len(V);
  pub const KEY_SCHEDULE_LEN: usize = Variant::key_schedule_len(V);

  pub fn new() -> Self
  {
    Control::initialize(V);
    Self {
      key_schedule: [0; Variant::key_schedule_len(V)],
    }
  }

  pub fn set_encrypt_key(&mut self, key: impl AsRef<[u8]>) -> Result<(), LenError>
  {
    if Variant::key_len(V) != key.as_ref().len() {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.as_ref().len(),
      });
    }
    let aes = Control::aes_table(V);
    unsafe { aes.expand_key(key.as_ref().as_ptr(), self.key_schedule.as_mut_ptr()) };
    Ok(())
  }

  pub fn set_decrypt_key(&mut self, key: impl AsRef<[u8]>) -> Result<(), LenError>
  {
    if Variant::key_len(V) != key.as_ref().len() {
      return Err(LenError {
        field: "key",
        expected: Variant::key_len(V),
        got: key.as_ref().len(),
      });
    }
    let aes = Control::aes_table(V);
    unsafe { aes.expand_key(key.as_ref().as_ptr(), self.key_schedule.as_mut_ptr()) };
    unsafe { aes.inverse_key(self.key_schedule.as_mut_ptr()) };
    Ok(())
  }

  pub unsafe fn set_encrypt_key_unchecked(&mut self, key: impl AsRef<[u8]>)
  {
    let aes = Control::aes_table(V);
    aes.expand_key(key.as_ref().as_ptr(), self.key_schedule.as_mut_ptr());
  }

  pub unsafe fn set_decrypt_key_unchecked(&mut self, key: impl AsRef<[u8]>)
  {
    let aes = Control::aes_table(V);
    aes.expand_key(key.as_ref().as_ptr(), self.key_schedule.as_mut_ptr());
    aes.inverse_key(self.key_schedule.as_mut_ptr());
  }

  pub fn inverse_key(&mut self)
  {
    let aes = Control::aes_table(V);
    unsafe { aes.inverse_key(self.key_schedule.as_mut_ptr()) };
  }

  pub fn encrypt_single(&self, mut block: impl AsMut<[u8]>) -> Result<(), LenError>
  {
    if block.as_mut().len() != 16 {
      return Err(LenError {
        field: "block",
        expected: 16,
        got: block.as_mut().len(),
      });
    }
    let aes = Control::aes_table(V);
    unsafe { aes.encrypt(block.as_mut().as_mut_ptr(), self.key_schedule.as_ptr()) };
    Ok(())
  }

  pub fn decrypt_single(&self, mut block: impl AsMut<[u8]>) -> Result<(), LenError>
  {
    if block.as_mut().len() != 16 {
      return Err(LenError {
        field: "block",
        expected: 16,
        got: block.as_mut().len(),
      });
    }
    let aes = Control::aes_table(V);
    unsafe { aes.decrypt(block.as_mut().as_mut_ptr(), self.key_schedule.as_ptr()) };
    Ok(())
  }

  pub unsafe fn encrypt_single_unchecked(&self, mut block: impl AsMut<[u8]>)
  {
    let aes = Control::aes_table(V);
    aes.encrypt(block.as_mut().as_mut_ptr(), self.key_schedule.as_ptr());
  }

  pub unsafe fn decrypt_single_unchecked(&self, mut block: impl AsMut<[u8]>)
  {
    let aes = Control::aes_table(V);
    aes.decrypt(block.as_mut().as_mut_ptr(), self.key_schedule.as_ptr());
  }
}

/// AES-128 algorithm.
pub type Aes128 = Aes<{ Variant::Aes128 }>;
/// AES-192 algorithm.
pub type Aes192 = Aes<{ Variant::Aes192 }>;
/// AES-256 algorithm.
pub type Aes256 = Aes<{ Variant::Aes256 }>;

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
