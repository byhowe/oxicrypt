#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesVectors<const K: usize, const S: usize>
{
  pub key: [u8; K],
  pub expanded_key: [u8; S],
  pub inversed_key: [u8; S],
  pub plaintext: [[u8; 16]; 8],
  pub ciphertext: [[u8; 16]; 8],
}

pub const AES128: &[AesVectors<16, 176>] = &include!(env!("BYTEST_AES128"));
pub const AES192: &[AesVectors<24, 208>] = &include!(env!("BYTEST_AES192"));
pub const AES256: &[AesVectors<32, 240>] = &include!(env!("BYTEST_AES256"));
