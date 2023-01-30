#[cfg(not(any(target_arch = "arm", target_arch = "aarch64", doc)))]
compile_error!("`aes_arm_aes_aes_encrypt` module is only available for `arm` and `aarch64`");

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;

#[inline(always)]
unsafe fn encrypt1<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  debug_assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));

  for i in 1 .. N {
    b0 = vaeseq_u8(b0, k0);
    b0 = vaesmcq_u8(b0);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaeseq_u8(b0, k0);

  k0 = vld1q_u8(key_schedule.add(N * 16));
  b0 = veorq_u8(b0, k0);

  vst1q_u8(block, b0);
}

#[inline(always)]
unsafe fn encrypt2<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  debug_assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));
  let mut b1: uint8x16_t = vld1q_u8(block.add(1 * 16));

  for i in 1 .. N {
    b0 = vaeseq_u8(b0, k0);
    b0 = vaesmcq_u8(b0);
    b1 = vaeseq_u8(b1, k0);
    b1 = vaesmcq_u8(b1);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaeseq_u8(b0, k0);
  b1 = vaeseq_u8(b1, k0);

  k0 = vld1q_u8(key_schedule.add(N * 16));
  b0 = veorq_u8(b0, k0);
  b1 = veorq_u8(b1, k0);

  vst1q_u8(block, b0);
  vst1q_u8(block, b1);
}

#[inline(always)]
unsafe fn encrypt4<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  debug_assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));
  let mut b1: uint8x16_t = vld1q_u8(block.add(1 * 16));
  let mut b2: uint8x16_t = vld1q_u8(block.add(2 * 16));
  let mut b3: uint8x16_t = vld1q_u8(block.add(3 * 16));

  for i in 1 .. N {
    b0 = vaeseq_u8(b0, k0);
    b0 = vaesmcq_u8(b0);
    b1 = vaeseq_u8(b1, k0);
    b1 = vaesmcq_u8(b1);
    b2 = vaeseq_u8(b2, k0);
    b2 = vaesmcq_u8(b2);
    b3 = vaeseq_u8(b3, k0);
    b3 = vaesmcq_u8(b3);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaeseq_u8(b0, k0);
  b1 = vaeseq_u8(b1, k0);
  b2 = vaeseq_u8(b2, k0);
  b3 = vaeseq_u8(b3, k0);

  k0 = vld1q_u8(key_schedule.add(N * 16));
  b0 = veorq_u8(b0, k0);
  b1 = veorq_u8(b1, k0);
  b2 = veorq_u8(b2, k0);
  b3 = veorq_u8(b3, k0);

  vst1q_u8(block, b0);
  vst1q_u8(block, b1);
  vst1q_u8(block, b2);
  vst1q_u8(block, b3);
}

#[inline(always)]
unsafe fn encrypt8<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  debug_assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));
  let mut b1: uint8x16_t = vld1q_u8(block.add(1 * 16));
  let mut b2: uint8x16_t = vld1q_u8(block.add(2 * 16));
  let mut b3: uint8x16_t = vld1q_u8(block.add(3 * 16));
  let mut b4: uint8x16_t = vld1q_u8(block.add(4 * 16));
  let mut b5: uint8x16_t = vld1q_u8(block.add(5 * 16));
  let mut b6: uint8x16_t = vld1q_u8(block.add(6 * 16));
  let mut b7: uint8x16_t = vld1q_u8(block.add(7 * 16));

  for i in 1 .. N {
    b0 = vaeseq_u8(b0, k0);
    b0 = vaesmcq_u8(b0);
    b1 = vaeseq_u8(b1, k0);
    b1 = vaesmcq_u8(b1);
    b2 = vaeseq_u8(b2, k0);
    b2 = vaesmcq_u8(b2);
    b3 = vaeseq_u8(b3, k0);
    b3 = vaesmcq_u8(b3);
    b4 = vaeseq_u8(b4, k0);
    b4 = vaesmcq_u8(b4);
    b5 = vaeseq_u8(b5, k0);
    b5 = vaesmcq_u8(b5);
    b6 = vaeseq_u8(b6, k0);
    b6 = vaesmcq_u8(b6);
    b7 = vaeseq_u8(b7, k0);
    b7 = vaesmcq_u8(b7);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaeseq_u8(b0, k0);
  b1 = vaeseq_u8(b1, k0);
  b2 = vaeseq_u8(b2, k0);
  b3 = vaeseq_u8(b3, k0);
  b4 = vaeseq_u8(b4, k0);
  b5 = vaeseq_u8(b5, k0);
  b6 = vaeseq_u8(b6, k0);
  b7 = vaeseq_u8(b7, k0);

  k0 = vld1q_u8(key_schedule.add(N * 16));
  b0 = veorq_u8(b0, k0);
  b1 = veorq_u8(b1, k0);
  b2 = veorq_u8(b2, k0);
  b3 = veorq_u8(b3, k0);
  b4 = veorq_u8(b4, k0);
  b5 = veorq_u8(b5, k0);
  b6 = veorq_u8(b6, k0);
  b7 = veorq_u8(b7, k0);

  vst1q_u8(block, b0);
  vst1q_u8(block, b1);
  vst1q_u8(block, b2);
  vst1q_u8(block, b3);
  vst1q_u8(block, b4);
  vst1q_u8(block, b5);
  vst1q_u8(block, b6);
  vst1q_u8(block, b7);
}

// AES128 ENCRYPT

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  encrypt1::<10>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  encrypt2::<10>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  encrypt4::<10>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  encrypt8::<10>(block, key_schedule);
}

// AES192 ENCRYPT

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  encrypt1::<12>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  encrypt2::<12>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  encrypt4::<12>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  encrypt8::<12>(block, key_schedule);
}

// AES256 ENCRYPT

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  encrypt1::<14>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  encrypt2::<14>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  encrypt4::<14>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  encrypt8::<14>(block, key_schedule);
}

#[cfg(test)]
mod tests
{
  use oxicrypt_test::Aes;
  use oxicrypt_test::AesVectorsIterator;

  use super::*;

  #[test]
  fn aes128()
  {
    for vectors in AesVectorsIterator::<{ Aes::Aes128 }>::new() {
      let mut block1 = vectors.plaintext_chunks()[0 .. 1].to_vec();
      let mut block2 = vectors.plaintext_chunks()[0 .. 2].to_vec();
      let mut block4 = vectors.plaintext_chunks()[0 .. 4].to_vec();
      let mut block8 = vectors.plaintext_chunks()[0 .. 8].to_vec();

      unsafe {
        aes_arm_aes_aes128_encrypt1(block1.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes128_encrypt2(block2.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes128_encrypt4(block4.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes128_encrypt8(block8.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
      }

      assert_eq!(block1, vectors.ciphertext_chunks()[0 .. 1]);
      assert_eq!(block2, vectors.ciphertext_chunks()[0 .. 2]);
      assert_eq!(block4, vectors.ciphertext_chunks()[0 .. 4]);
      assert_eq!(block8, vectors.ciphertext_chunks()[0 .. 8]);
    }
  }

  #[test]
  fn aes192()
  {
    for vectors in AesVectorsIterator::<{ Aes::Aes192 }>::new() {
      let mut block1 = vectors.plaintext_chunks()[0 .. 1].to_vec();
      let mut block2 = vectors.plaintext_chunks()[0 .. 2].to_vec();
      let mut block4 = vectors.plaintext_chunks()[0 .. 4].to_vec();
      let mut block8 = vectors.plaintext_chunks()[0 .. 8].to_vec();

      unsafe {
        aes_arm_aes_aes192_encrypt1(block1.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes192_encrypt2(block2.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes192_encrypt4(block4.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes192_encrypt8(block8.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
      }

      assert_eq!(block1, vectors.ciphertext_chunks()[0 .. 1]);
      assert_eq!(block2, vectors.ciphertext_chunks()[0 .. 2]);
      assert_eq!(block4, vectors.ciphertext_chunks()[0 .. 4]);
      assert_eq!(block8, vectors.ciphertext_chunks()[0 .. 8]);
    }
  }

  #[test]
  fn aes256()
  {
    for vectors in AesVectorsIterator::<{ Aes::Aes256 }>::new() {
      let mut block1 = vectors.plaintext_chunks()[0 .. 1].to_vec();
      let mut block2 = vectors.plaintext_chunks()[0 .. 2].to_vec();
      let mut block4 = vectors.plaintext_chunks()[0 .. 4].to_vec();
      let mut block8 = vectors.plaintext_chunks()[0 .. 8].to_vec();

      unsafe {
        aes_arm_aes_aes256_encrypt1(block1.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes256_encrypt2(block2.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes256_encrypt4(block4.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_arm_aes_aes256_encrypt8(block8.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
      }

      assert_eq!(block1, vectors.ciphertext_chunks()[0 .. 1]);
      assert_eq!(block2, vectors.ciphertext_chunks()[0 .. 2]);
      assert_eq!(block4, vectors.ciphertext_chunks()[0 .. 4]);
      assert_eq!(block8, vectors.ciphertext_chunks()[0 .. 8]);
    }
  }
}
