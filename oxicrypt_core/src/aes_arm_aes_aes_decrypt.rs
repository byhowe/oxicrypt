#[cfg(not(any(target_arch = "arm", target_arch = "aarch64", doc)))]
compile_error!("`aes_arm_aes_aes_decrypt` module is only available for `arm` and `aarch64`");

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;

#[inline(always)]
unsafe fn decrypt1<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));

  for i in 1 .. N {
    b0 = vaesdq_u8(b0, k0);
    b0 = vaesimcq_u8(b0);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaesdq_u8(b0, k0);

  k0 = vld1q_u8(key_schedule.add(N * 16));
  b0 = veorq_u8(b0, k0);

  vst1q_u8(block, b0);
}

#[inline(always)]
unsafe fn decrypt2<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));
  let mut b1: uint8x16_t = vld1q_u8(block.add(1 * 16));

  for i in 1 .. N {
    b0 = vaesdq_u8(b0, k0);
    b0 = vaesimcq_u8(b0);
    b1 = vaesdq_u8(b1, k0);
    b1 = vaesimcq_u8(b1);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaesdq_u8(b0, k0);
  b1 = vaesdq_u8(b1, k0);

  k0 = vld1q_u8(key_schedule.add(N * 16));
  b0 = veorq_u8(b0, k0);
  b1 = veorq_u8(b1, k0);

  vst1q_u8(block, b0);
  vst1q_u8(block, b1);
}

#[inline(always)]
unsafe fn decrypt4<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: uint8x16_t = vld1q_u8(key_schedule.add(0 * 16));
  let mut b0: uint8x16_t = vld1q_u8(block.add(0 * 16));
  let mut b1: uint8x16_t = vld1q_u8(block.add(1 * 16));
  let mut b2: uint8x16_t = vld1q_u8(block.add(2 * 16));
  let mut b3: uint8x16_t = vld1q_u8(block.add(3 * 16));

  for i in 1 .. N {
    b0 = vaesdq_u8(b0, k0);
    b0 = vaesimcq_u8(b0);
    b1 = vaesdq_u8(b1, k0);
    b1 = vaesimcq_u8(b1);
    b2 = vaesdq_u8(b2, k0);
    b2 = vaesimcq_u8(b2);
    b3 = vaesdq_u8(b3, k0);
    b3 = vaesimcq_u8(b3);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaesdq_u8(b0, k0);
  b1 = vaesdq_u8(b1, k0);
  b2 = vaesdq_u8(b2, k0);
  b3 = vaesdq_u8(b3, k0);

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
unsafe fn decrypt8<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

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
    b0 = vaesdq_u8(b0, k0);
    b0 = vaesimcq_u8(b0);
    b1 = vaesdq_u8(b1, k0);
    b1 = vaesimcq_u8(b1);
    b2 = vaesdq_u8(b2, k0);
    b2 = vaesimcq_u8(b2);
    b3 = vaesdq_u8(b3, k0);
    b3 = vaesimcq_u8(b3);
    b4 = vaesdq_u8(b4, k0);
    b4 = vaesimcq_u8(b4);
    b5 = vaesdq_u8(b5, k0);
    b5 = vaesimcq_u8(b5);
    b6 = vaesdq_u8(b6, k0);
    b6 = vaesimcq_u8(b6);
    b7 = vaesdq_u8(b7, k0);
    b7 = vaesimcq_u8(b7);

    k0 = vld1q_u8(key_schedule.add(i * 16));
  }

  b0 = vaesdq_u8(b0, k0);
  b1 = vaesdq_u8(b1, k0);
  b2 = vaesdq_u8(b2, k0);
  b3 = vaesdq_u8(b3, k0);
  b4 = vaesdq_u8(b4, k0);
  b5 = vaesdq_u8(b5, k0);
  b6 = vaesdq_u8(b6, k0);
  b7 = vaesdq_u8(b7, k0);

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

// AES128 DECRYPT

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  decrypt1::<10>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  decrypt2::<10>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  decrypt4::<10>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes128_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  decrypt8::<10>(block, key_schedule);
}

// AES192 DECRYPT

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  decrypt1::<12>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  decrypt2::<12>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  decrypt4::<12>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes192_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  decrypt8::<12>(block, key_schedule);
}

// AES256 DECRYPT

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  decrypt1::<14>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  decrypt2::<14>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  decrypt4::<14>(block, key_schedule);
}

#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "arm", target_arch = "aarch64")))]
pub unsafe fn aes_arm_aes_aes256_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  decrypt8::<14>(block, key_schedule);
}