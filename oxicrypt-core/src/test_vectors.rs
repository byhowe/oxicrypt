pub const AES128_EXPAND_KEY: &[([u8; 16], [u8; 176])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes128-expand-key.txt"));
pub const AES192_EXPAND_KEY: &[([u8; 24], [u8; 208])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes192-expand-key.txt"));
pub const AES256_EXPAND_KEY: &[([u8; 32], [u8; 240])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes256-expand-key.txt"));

pub const AES128_INVERSE_KEY: &[([u8; 176], [u8; 176])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes128-inverse-key.txt"));
pub const AES192_INVERSE_KEY: &[([u8; 208], [u8; 208])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes192-inverse-key.txt"));
pub const AES256_INVERSE_KEY: &[([u8; 240], [u8; 240])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes256-inverse-key.txt"));

pub const AES128_ENCRYPT: &[([u8; 16], [u8; 16], [u8; 176])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes128-encrypt.txt"));
pub const AES192_ENCRYPT: &[([u8; 16], [u8; 16], [u8; 208])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes192-encrypt.txt"));
pub const AES256_ENCRYPT: &[([u8; 16], [u8; 16], [u8; 240])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes256-encrypt.txt"));

pub const AES128_DECRYPT: &[([u8; 16], [u8; 16], [u8; 176])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes128-decrypt.txt"));
pub const AES192_DECRYPT: &[([u8; 16], [u8; 16], [u8; 208])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes192-decrypt.txt"));
pub const AES256_DECRYPT: &[([u8; 16], [u8; 16], [u8; 240])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes256-decrypt.txt"));

pub const AES128_ENCRYPT_DECRYPT: &[([u8; 16], [u8; 16], [u8; 16])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes128-encrypt-decrypt.txt"));
pub const AES192_ENCRYPT_DECRYPT: &[([u8; 16], [u8; 16], [u8; 24])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes192-encrypt-decrypt.txt"));
pub const AES256_ENCRYPT_DECRYPT: &[([u8; 16], [u8; 16], [u8; 32])] =
  &include!(concat!(env!("OXICRYPT_TEST_VECS"), "aes256-encrypt-decrypt.txt"));
