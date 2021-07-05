pub const SHA1_COMPRESS: &[([u32; 5], [u32; 5], [u8; 64])] = &include!(env!("OXI_TEST_sha1-compress.txt"));
pub const SHA256_COMPRESS: &[([u32; 8], [u32; 8], [u8; 64])] = &include!(env!("OXI_TEST_sha256-compress.txt"));
pub const SHA512_COMPRESS: &[([u64; 8], [u64; 8], [u8; 128])] = &include!(env!("OXI_TEST_sha512-compress.txt"));

pub const AES128_EXPAND_KEY: &[([u8; 16], [u8; 176])] = &include!(env!("OXI_TEST_aes128-expand-key.txt"));
pub const AES192_EXPAND_KEY: &[([u8; 24], [u8; 208])] = &include!(env!("OXI_TEST_aes192-expand-key.txt"));
pub const AES256_EXPAND_KEY: &[([u8; 32], [u8; 240])] = &include!(env!("OXI_TEST_aes256-expand-key.txt"));

pub const AES128_INVERSE_KEY: &[([u8; 176], [u8; 176])] = &include!(env!("OXI_TEST_aes128-inverse-key.txt"));
pub const AES192_INVERSE_KEY: &[([u8; 208], [u8; 208])] = &include!(env!("OXI_TEST_aes192-inverse-key.txt"));
pub const AES256_INVERSE_KEY: &[([u8; 240], [u8; 240])] = &include!(env!("OXI_TEST_aes256-inverse-key.txt"));

pub const AES128_ENCRYPT: &[([u8; 16], [u8; 16], [u8; 176])] = &include!(env!("OXI_TEST_aes128-encrypt.txt"));
pub const AES192_ENCRYPT: &[([u8; 16], [u8; 16], [u8; 208])] = &include!(env!("OXI_TEST_aes192-encrypt.txt"));
pub const AES256_ENCRYPT: &[([u8; 16], [u8; 16], [u8; 240])] = &include!(env!("OXI_TEST_aes256-encrypt.txt"));

pub const AES128_DECRYPT: &[([u8; 16], [u8; 16], [u8; 176])] = &include!(env!("OXI_TEST_aes128-decrypt.txt"));
pub const AES192_DECRYPT: &[([u8; 16], [u8; 16], [u8; 208])] = &include!(env!("OXI_TEST_aes192-decrypt.txt"));
pub const AES256_DECRYPT: &[([u8; 16], [u8; 16], [u8; 240])] = &include!(env!("OXI_TEST_aes256-decrypt.txt"));

pub const AES128_ENCRYPT_DECRYPT: &[([u8; 16], [u8; 16], [u8; 16])] =
  &include!(env!("OXI_TEST_aes128-encrypt-decrypt.txt"));
pub const AES192_ENCRYPT_DECRYPT: &[([u8; 16], [u8; 16], [u8; 24])] =
  &include!(env!("OXI_TEST_aes192-encrypt-decrypt.txt"));
pub const AES256_ENCRYPT_DECRYPT: &[([u8; 16], [u8; 16], [u8; 32])] =
  &include!(env!("OXI_TEST_aes256-encrypt-decrypt.txt"));

pub mod cavp
{
  pub const SHA1: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha1_test_vectors.txt"));
  pub const SHA224: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha224_test_vectors.txt"));
  pub const SHA256: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha256_test_vectors.txt"));
  pub const SHA384: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha384_test_vectors.txt"));
  pub const SHA512: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha512_test_vectors.txt"));
  pub const SHA512_224: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha512_224_test_vectors.txt"));
  pub const SHA512_256: &[(&str, &str, usize)] = &include!(env!("OXI_CAVP_sha512_256_test_vectors.txt"));
}
