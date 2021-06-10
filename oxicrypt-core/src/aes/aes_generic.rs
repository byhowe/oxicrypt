#![allow(unused_variables)]
#![allow(clippy::missing_safety_doc)]

#[inline(always)]
pub unsafe fn aes128_expand_key_generic(key: *const u8, key_schedule: *mut u8) {}

#[inline(always)]
pub unsafe fn aes192_expand_key_generic(key: *const u8, key_schedule: *mut u8) {}

#[inline(always)]
pub unsafe fn aes256_expand_key_generic(key: *const u8, key_schedule: *mut u8) {}

#[inline(always)]
pub unsafe fn aes128_inverse_key_generic(key_schedule: *mut u8) {}

#[inline(always)]
pub unsafe fn aes192_inverse_key_generic(key_schedule: *mut u8) {}

#[inline(always)]
pub unsafe fn aes256_inverse_key_generic(key_schedule: *mut u8) {}

#[inline(always)]
pub unsafe fn aes128_encrypt_generic(block: *mut u8, key_schedule: *const u8) {}

#[inline(always)]
pub unsafe fn aes192_encrypt_generic(block: *mut u8, key_schedule: *const u8) {}

#[inline(always)]
pub unsafe fn aes256_encrypt_generic(block: *mut u8, key_schedule: *const u8) {}

#[inline(always)]
pub unsafe fn aes128_decrypt_generic(block: *mut u8, key_schedule: *const u8) {}

#[inline(always)]
pub unsafe fn aes192_decrypt_generic(block: *mut u8, key_schedule: *const u8) {}

#[inline(always)]
pub unsafe fn aes256_decrypt_generic(block: *mut u8, key_schedule: *const u8) {}

// #[cfg(test)]
// mod tests
// {
//   extern crate std;
//
//   use super::*;
//
//   #[test]
//   fn test_aes128_expand_key()
//   {
//     let tests: &[([u8; 16], [u8; 176])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes128-expand-key.txt"
//     ));
//     let mut key_schedule = [0; 176];
//     tests.iter().for_each(|t| {
//       unsafe { aes128_expand_key_generic(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
//       assert_eq!(t.1, key_schedule);
//     });
//   }
//
//   #[test]
//   fn test_aes192_expand_key()
//   {
//     let tests: &[([u8; 24], [u8; 208])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes192-expand-key.txt"
//     ));
//     let mut key_schedule = [0; 208];
//     tests.iter().for_each(|t| {
//       unsafe { aes192_expand_key_generic(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
//       assert_eq!(t.1, key_schedule);
//     });
//   }
//
//   #[test]
//   fn test_aes256_expand_key()
//   {
//     let tests: &[([u8; 32], [u8; 240])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes256-expand-key.txt"
//     ));
//     let mut key_schedule = [0; 240];
//     tests.iter().for_each(|t| {
//       unsafe { aes256_expand_key_generic(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
//       assert_eq!(t.1, key_schedule);
//     });
//   }
//
//   #[test]
//   fn test_aes128_inverse_key()
//   {
//     let tests: &[([u8; 176], [u8; 176])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes128-inverse-key.txt"
//     ));
//     let mut key_schedule = [0; 176];
//     tests.iter().for_each(|t| {
//       key_schedule = t.0;
//       unsafe { aes128_inverse_key_generic(key_schedule.as_mut_ptr()) };
//       assert_eq!(t.1, key_schedule);
//     });
//   }
//
//   #[test]
//   fn test_aes192_inverse_key()
//   {
//     let tests: &[([u8; 208], [u8; 208])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes192-inverse-key.txt"
//     ));
//     let mut key_schedule = [0; 208];
//     tests.iter().for_each(|t| {
//       key_schedule = t.0;
//       unsafe { aes192_inverse_key_generic(key_schedule.as_mut_ptr()) };
//       assert_eq!(t.1, key_schedule);
//     });
//   }
//
//   #[test]
//   fn test_aes256_inverse_key()
//   {
//     let tests: &[([u8; 240], [u8; 240])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes256-inverse-key.txt"
//     ));
//     let mut key_schedule = [0; 240];
//     tests.iter().for_each(|t| {
//       key_schedule = t.0;
//       unsafe { aes256_inverse_key_generic(key_schedule.as_mut_ptr()) };
//       assert_eq!(t.1, key_schedule);
//     });
//   }
//
//   #[test]
//   fn test_aes128_encrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 176])] =
//       &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes128-encrypt.txt"));
//     let mut block = [0; 16];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes128_encrypt_generic(block.as_mut_ptr(), t.2.as_ptr()) };
//       assert_eq!(t.1, block);
//     });
//   }
//
//   #[test]
//   fn test_aes192_encrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 208])] =
//       &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes192-encrypt.txt"));
//     let mut block = [0; 16];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes192_encrypt_generic(block.as_mut_ptr(), t.2.as_ptr()) };
//       assert_eq!(t.1, block);
//     });
//   }
//
//   #[test]
//   fn test_aes256_encrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 240])] =
//       &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes256-encrypt.txt"));
//     let mut block = [0; 16];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes256_encrypt_generic(block.as_mut_ptr(), t.2.as_ptr()) };
//       assert_eq!(t.1, block);
//     });
//   }
//
//   #[test]
//   fn test_aes128_decrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 176])] =
//       &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes128-decrypt.txt"));
//     let mut block = [0; 16];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes128_decrypt_generic(block.as_mut_ptr(), t.2.as_ptr()) };
//       assert_eq!(t.1, block);
//     });
//   }
//
//   #[test]
//   fn test_aes192_decrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 208])] =
//       &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes192-decrypt.txt"));
//     let mut block = [0; 16];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes192_decrypt_generic(block.as_mut_ptr(), t.2.as_ptr()) };
//       assert_eq!(t.1, block);
//     });
//   }
//
//   #[test]
//   fn test_aes256_decrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 240])] =
//       &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes256-decrypt.txt"));
//     let mut block = [0; 16];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes256_decrypt_generic(block.as_mut_ptr(), t.2.as_ptr()) };
//       assert_eq!(t.1, block);
//     });
//   }
//
//   #[test]
//   fn test_aes128_encrypt_decrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 16])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes128-encrypt-decrypt.txt"
//     ));
//     let mut block = [0; 16];
//     let mut key_schedule = [0; 176];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes128_expand_key_generic(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
//       unsafe { aes128_encrypt_generic(block.as_mut_ptr(), key_schedule.as_ptr()) };
//       assert_eq!(t.1, block);
//       unsafe { aes128_inverse_key_generic(key_schedule.as_mut_ptr()) };
//       unsafe { aes128_decrypt_generic(block.as_mut_ptr(), key_schedule.as_ptr()) };
//       assert_eq!(t.0, block);
//     });
//   }
//
//   #[test]
//   fn test_aes192_encrypt_decrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 24])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes192-encrypt-decrypt.txt"
//     ));
//     let mut block = [0; 16];
//     let mut key_schedule = [0; 208];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes192_expand_key_generic(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
//       unsafe { aes192_encrypt_generic(block.as_mut_ptr(), key_schedule.as_ptr()) };
//       assert_eq!(t.1, block);
//       unsafe { aes192_inverse_key_generic(key_schedule.as_mut_ptr()) };
//       unsafe { aes192_decrypt_generic(block.as_mut_ptr(), key_schedule.as_ptr()) };
//       assert_eq!(t.0, block);
//     });
//   }
//
//   #[test]
//   fn test_aes256_encrypt_decrypt()
//   {
//     let tests: &[([u8; 16], [u8; 16], [u8; 32])] = &include!(concat!(
//       env!("CARGO_MANIFEST_DIR"),
//       "/test-vectors/aes256-encrypt-decrypt.txt"
//     ));
//     let mut block = [0; 16];
//     let mut key_schedule = [0; 240];
//     tests.iter().for_each(|t| {
//       block = t.0;
//       unsafe { aes256_expand_key_generic(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
//       unsafe { aes256_encrypt_generic(block.as_mut_ptr(), key_schedule.as_ptr()) };
//       assert_eq!(t.1, block);
//       unsafe { aes256_inverse_key_generic(key_schedule.as_mut_ptr()) };
//       unsafe { aes256_decrypt_generic(block.as_mut_ptr(), key_schedule.as_ptr()) };
//       assert_eq!(t.0, block);
//     });
//   }
// }
