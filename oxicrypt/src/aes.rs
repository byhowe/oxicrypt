pub struct Aes128
{
  round_keys: [u8; 176],
}

impl Aes128
{
  pub const fn new() -> Self
  {
    Self { round_keys: [0; 176] }
  }

  pub fn set_encrypt_key(&mut self, key: &[u8]) -> Result<(), Error>
  {
    if key.len() != 16 {
      return Err(Error::KeyLength {
        expected: 16,
        got: key.len(),
      });
    }
    unsafe {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      oxicrypt_core::aes::aes128_expand_encrypt_key_x86_aesni(key.as_ptr(), self.round_keys.as_mut_ptr());
      #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
      oxicrypt_core::aes::aes128_expand_encrypt_key_generic(key.as_ptr(), self.round_keys.as_mut_ptr());
    };
    Ok(())
  }

  pub fn set_decrypt_key(&mut self, key: &[u8]) -> Result<(), Error>
  {
    if key.len() != 16 {
      return Err(Error::KeyLength {
        expected: 16,
        got: key.len(),
      });
    }
    unsafe {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      oxicrypt_core::aes::aes128_expand_decrypt_key_x86_aesni(key.as_ptr(), self.round_keys.as_mut_ptr());
      #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
      oxicrypt_core::aes::aes128_expand_decrypt_key_generic(key.as_ptr(), self.round_keys.as_mut_ptr());
    };
    Ok(())
  }

  pub fn encrypt(&self, data: &mut [u8]) -> Result<(), Error>
  {
    if data.len() != 16 {
      return Err(Error::DataLength {
        expected: 16,
        got: data.len(),
      });
    }
    unsafe {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      oxicrypt_core::aes::aes128_encrypt_x86_aesni(data.as_mut_ptr(), self.round_keys.as_ptr());
      #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
      oxicrypt_core::aes::aes128_encrypt_generic(data.as_mut_ptr(), self.round_keys.as_ptr());
    };
    Ok(())
  }

  pub fn decrypt(&self, data: &mut [u8]) -> Result<(), Error>
  {
    if data.len() != 16 {
      return Err(Error::DataLength {
        expected: 16,
        got: data.len(),
      });
    }
    unsafe {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      oxicrypt_core::aes::aes128_decrypt_x86_aesni(data.as_mut_ptr(), self.round_keys.as_ptr());
      #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
      oxicrypt_core::aes::aes128_decrypt_generic(data.as_mut_ptr(), self.round_keys.as_ptr());
    };
    Ok(())
  }
}

#[derive(Debug)]
pub enum Error
{
  KeyLength
  {
    expected: usize, got: usize
  },
  DataLength
  {
    expected: usize, got: usize
  },
}
