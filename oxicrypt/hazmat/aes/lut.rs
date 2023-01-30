#![allow(clippy::identity_op)]


#[cfg(test)]
mod tests
{
  use super::*;
  use crate::hazmat::aes::Variant;
  use crate::test_vectors::*;

  #[test]
  fn test_expand_key()
  {
    AES128_EXPAND_KEY.iter().for_each(|t| {
      let mut key_schedule = [0; Variant::key_schedule_len(Variant::Aes128)];
      unsafe { aes128_expand_key(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
    AES192_EXPAND_KEY.iter().for_each(|t| {
      let mut key_schedule = [0; Variant::key_schedule_len(Variant::Aes192)];
      unsafe { aes192_expand_key(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
    AES256_EXPAND_KEY.iter().for_each(|t| {
      let mut key_schedule = [0; Variant::key_schedule_len(Variant::Aes256)];
      unsafe { aes256_expand_key(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  fn test_inverse_key()
  {
    AES128_INVERSE_KEY.iter().for_each(|t| {
      let mut key_schedule = t.0;
      unsafe { aes128_inverse_key(key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
    AES192_INVERSE_KEY.iter().for_each(|t| {
      let mut key_schedule = t.0;
      unsafe { aes192_inverse_key(key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
    AES256_INVERSE_KEY.iter().for_each(|t| {
      let mut key_schedule = t.0;
      unsafe { aes256_inverse_key(key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  fn test_encrypt()
  {
    AES128_ENCRYPT.iter().for_each(|t| {
      let mut block = t.0;
      unsafe { aes128_encrypt1(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
    AES192_ENCRYPT.iter().for_each(|t| {
      let mut block = t.0;
      unsafe { aes192_encrypt1(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
    AES256_ENCRYPT.iter().for_each(|t| {
      let mut block = t.0;
      unsafe { aes256_encrypt1(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  fn test_decrypt()
  {
    AES128_DECRYPT.iter().for_each(|t| {
      let mut block = t.0;
      unsafe { aes128_decrypt1(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
    AES192_DECRYPT.iter().for_each(|t| {
      let mut block = t.0;
      unsafe { aes192_decrypt1(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
    AES256_DECRYPT.iter().for_each(|t| {
      let mut block = t.0;
      unsafe { aes256_decrypt1(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  fn test_encrypt_decrypt()
  {
    AES128_ENCRYPT_DECRYPT.iter().for_each(|t| {
      let mut block = t.0;
      let mut key_schedule = [0; Variant::key_schedule_len(Variant::Aes128)];
      unsafe { aes128_expand_key(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
      unsafe { aes128_encrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.1, block);
      unsafe { aes128_inverse_key(key_schedule.as_mut_ptr()) };
      unsafe { aes128_decrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.0, block);
    });
    AES192_ENCRYPT_DECRYPT.iter().for_each(|t| {
      let mut block = t.0;
      let mut key_schedule = [0; Variant::key_schedule_len(Variant::Aes192)];
      unsafe { aes192_expand_key(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
      unsafe { aes192_encrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.1, block);
      unsafe { aes192_inverse_key(key_schedule.as_mut_ptr()) };
      unsafe { aes192_decrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.0, block);
    });
    AES256_ENCRYPT_DECRYPT.iter().for_each(|t| {
      let mut block = t.0;
      let mut key_schedule = [0; Variant::key_schedule_len(Variant::Aes256)];
      unsafe { aes256_expand_key(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
      unsafe { aes256_encrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.1, block);
      unsafe { aes256_inverse_key(key_schedule.as_mut_ptr()) };
      unsafe { aes256_decrypt1(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.0, block);
    });
  }
}
