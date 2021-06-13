#![allow(clippy::missing_safety_doc)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
#[cfg(not(doc))]
unsafe fn expand_round<const IMM8: i32>(mut k: __m128i, mut kr: __m128i) -> __m128i
{
  kr = _mm_shuffle_epi32::<IMM8>(kr);
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  _mm_xor_si128(k, kr)
}

#[inline(always)]
unsafe fn aes128_expand_key(key: *const u8, key_schedule: *mut u8)
{
  let mut k: __m128i = _mm_loadu_si128(key as *const __m128i);
  _mm_storeu_si128(key_schedule as *mut __m128i, k);

  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x01>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(1), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x02>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(2), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x04>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(3), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x08>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(4), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x10>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(5), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x20>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(6), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x40>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(7), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x80>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(8), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x1b>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(9), k);
  k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x36>(k));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(10), k);
}

#[inline(always)]
unsafe fn aes192_expand_key(key: *const u8, key_schedule: *mut u8)
{
  #[inline(always)]
  #[cfg(not(doc))]
  unsafe fn expand_round_half(mut k1: __m128i, k0: __m128i) -> __m128i
  {
    k1 = _mm_xor_si128(k1, _mm_slli_si128::<4>(k1));
    _mm_xor_si128(k1, _mm_shuffle_epi32::<0xff>(k0))
  }

  let mut k0: __m128i = _mm_loadu_si128(key.add(0) as *const __m128i);
  let mut k1: __m128i = _mm_loadu_si128(key.add(8) as *const __m128i);
  k1 = _mm_srli_si128::<8>(k1);
  _mm_storeu_si128(key_schedule.add(0) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(16) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x01>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(24) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(40) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x02>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(48) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(64) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x04>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(72) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(88) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x08>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(96) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(112) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x10>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(120) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(136) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x20>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(144) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(160) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x40>(k1));
  k1 = expand_round_half(k1, k0);
  _mm_storeu_si128(key_schedule.add(168) as *mut __m128i, k0);
  _mm_storeu_si128(key_schedule.add(184) as *mut __m128i, k1);

  k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x80>(k1));
  _mm_storeu_si128(key_schedule.add(192) as *mut __m128i, k0);
}

#[inline(always)]
unsafe fn aes256_expand_key(key: *const u8, key_schedule: *mut u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key as *const __m128i).add(0));
  let mut k1: __m128i = _mm_loadu_si128((key as *const __m128i).add(1));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(0), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(1), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x01>(k1));
  k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(2), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(3), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x02>(k1));
  k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(4), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(5), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x04>(k1));
  k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(6), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(7), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x08>(k1));
  k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(8), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(9), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x10>(k1));
  k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(10), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(11), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x20>(k1));
  k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(12), k0);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(13), k1);

  k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x40>(k1));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(14), k0);
}

#[inline(always)]
unsafe fn aes_inverse_key<const N: usize>(key_schedule: *mut u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut k1: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(0), k1);
  _mm_storeu_si128((key_schedule as *mut __m128i).add(N), k0);

  // Compiler is able to unroll this loop.
  for i in 1 .. N / 2 {
    k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(i)));
    k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(N - i)));
    _mm_storeu_si128((key_schedule as *mut __m128i).add(i), k1);
    _mm_storeu_si128((key_schedule as *mut __m128i).add(N - i), k0);
  }

  k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(N / 2)));
  _mm_storeu_si128((key_schedule as *mut __m128i).add(N / 2), k0);
}

#[inline(always)]
unsafe fn aes_encrypt<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut b0: __m128i = _mm_loadu_si128(block as *const __m128i);
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

  b0 = _mm_xor_si128(b0, k0); // whitening round (round 0)

  // Compiler is able to unroll this loop.
  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N)); // round 10
  b0 = _mm_aesenclast_si128(b0, k0);

  _mm_storeu_si128(block as *mut __m128i, b0);
}

#[inline(always)]
unsafe fn aes_decrypt<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut b0: __m128i = _mm_loadu_si128(block as *const __m128i);
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

  b0 = _mm_xor_si128(b0, k0); // whitening round (round 0)

  // Compiler is able to unroll this loop.
  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N)); // round 10
  b0 = _mm_aesdeclast_si128(b0, k0);

  _mm_storeu_si128(block as *mut __m128i, b0);
}

// AES expand key functions.

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes128_expand_key_x86_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes128_expand_key(key, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes192_expand_key_x86_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes192_expand_key(key, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes256_expand_key_x86_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes256_expand_key(key, key_schedule);
}

// AES expand key functions with AVX.

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes128_expand_key_x86_avx_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes128_expand_key(key, key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes192_expand_key_x86_avx_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes192_expand_key(key, key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes256_expand_key_x86_avx_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes256_expand_key(key, key_schedule);
}

// AES inverse key functions.

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes128_inverse_key_x86_aesni(key_schedule: *mut u8)
{
  aes_inverse_key::<10>(key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes192_inverse_key_x86_aesni(key_schedule: *mut u8)
{
  aes_inverse_key::<12>(key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes256_inverse_key_x86_aesni(key_schedule: *mut u8)
{
  aes_inverse_key::<14>(key_schedule);
}

// AES inverse key functions with AVX.

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes128_inverse_key_x86_avx_aesni(key_schedule: *mut u8)
{
  aes_inverse_key::<10>(key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes192_inverse_key_x86_avx_aesni(key_schedule: *mut u8)
{
  aes_inverse_key::<12>(key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes256_inverse_key_x86_avx_aesni(key_schedule: *mut u8)
{
  aes_inverse_key::<14>(key_schedule);
}

// AES encrypt functions.

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes128_encrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes192_encrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes256_encrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt::<14>(block, key_schedule);
}

// AES encrypt functions with AVX.

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes128_encrypt_x86_avx_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt::<10>(block, key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes192_encrypt_x86_avx_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt::<12>(block, key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes256_encrypt_x86_avx_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt::<14>(block, key_schedule);
}

// AES decrypt functions.

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes128_decrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes192_decrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(all(
  any(target_arch = "x86", target_arch = "x86_64"),
  not(target_feature = "avx"),
  feature = "aesni"
)))]
#[cfg(not(target_feature = "avx"))]
#[inline]
pub unsafe fn aes256_decrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt::<14>(block, key_schedule);
}

// AES decrypt functions with AVX.

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes128_decrypt_x86_avx_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt::<10>(block, key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes192_decrypt_x86_avx_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt::<12>(block, key_schedule);
}

#[target_feature(enable = "avx,aes")]
#[doc(cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "aesni")))]
#[inline]
pub unsafe fn aes256_decrypt_x86_avx_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt::<14>(block, key_schedule);
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::*;

  #[test]
  fn test_aes128_expand_key()
  {
    if is_x86_feature_detected!("aes") {
      let mut key_schedule = [0; 176];
      AES128_EXPAND_KEY.iter().for_each(|t| {
        unsafe { aes128_expand_key_x86_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut key_schedule = [0; 176];
      AES128_EXPAND_KEY.iter().for_each(|t| {
        unsafe { aes128_expand_key_x86_avx_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
  }

  #[test]
  fn test_aes192_expand_key()
  {
    if is_x86_feature_detected!("aes") {
      let mut key_schedule = [0; 208];
      AES192_EXPAND_KEY.iter().for_each(|t| {
        unsafe { aes192_expand_key_x86_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut key_schedule = [0; 208];
      AES192_EXPAND_KEY.iter().for_each(|t| {
        unsafe { aes192_expand_key_x86_avx_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
  }

  #[test]
  fn test_aes256_expand_key()
  {
    if is_x86_feature_detected!("aes") {
      let mut key_schedule = [0; 240];
      AES256_EXPAND_KEY.iter().for_each(|t| {
        unsafe { aes256_expand_key_x86_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut key_schedule = [0; 240];
      AES256_EXPAND_KEY.iter().for_each(|t| {
        unsafe { aes256_expand_key_x86_avx_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
  }

  #[test]
  fn test_aes128_inverse_key()
  {
    if is_x86_feature_detected!("aes") {
      let mut key_schedule = [0; 176];
      AES128_INVERSE_KEY.iter().for_each(|t| {
        key_schedule = t.0;
        unsafe { aes128_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut key_schedule = [0; 176];
      AES128_INVERSE_KEY.iter().for_each(|t| {
        key_schedule = t.0;
        unsafe { aes128_inverse_key_x86_avx_aesni(key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
  }

  #[test]
  fn test_aes192_inverse_key()
  {
    if is_x86_feature_detected!("aes") {
      let mut key_schedule = [0; 208];
      AES192_INVERSE_KEY.iter().for_each(|t| {
        key_schedule = t.0;
        unsafe { aes192_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut key_schedule = [0; 208];
      AES192_INVERSE_KEY.iter().for_each(|t| {
        key_schedule = t.0;
        unsafe { aes192_inverse_key_x86_avx_aesni(key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
  }

  #[test]
  fn test_aes256_inverse_key()
  {
    if is_x86_feature_detected!("aes") {
      let mut key_schedule = [0; 240];
      AES256_INVERSE_KEY.iter().for_each(|t| {
        key_schedule = t.0;
        unsafe { aes256_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut key_schedule = [0; 240];
      AES256_INVERSE_KEY.iter().for_each(|t| {
        key_schedule = t.0;
        unsafe { aes256_inverse_key_x86_avx_aesni(key_schedule.as_mut_ptr()) };
        assert_eq!(t.1, key_schedule);
      });
    }
  }

  #[test]
  fn test_aes128_encrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      AES128_ENCRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes128_encrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      AES128_ENCRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes128_encrypt_x86_avx_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
  }

  #[test]
  fn test_aes192_encrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      AES192_ENCRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes192_encrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      AES192_ENCRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes192_encrypt_x86_avx_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
  }

  #[test]
  fn test_aes256_encrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      AES256_ENCRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes256_encrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      AES256_ENCRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes256_encrypt_x86_avx_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
  }

  #[test]
  fn test_aes128_decrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      AES128_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes128_decrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      AES128_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes128_decrypt_x86_avx_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
  }

  #[test]
  fn test_aes192_decrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      AES192_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes192_decrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      AES192_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes192_decrypt_x86_avx_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
  }

  #[test]
  fn test_aes256_decrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      AES256_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes256_decrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      AES256_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes256_decrypt_x86_avx_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
        assert_eq!(t.1, block);
      });
    }
  }

  #[test]
  fn test_aes128_encrypt_decrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      let mut key_schedule = [0; 176];
      AES128_ENCRYPT_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes128_expand_key_x86_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
        unsafe { aes128_encrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.1, block);
        unsafe { aes128_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
        unsafe { aes128_decrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.0, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      let mut key_schedule = [0; 176];
      AES128_ENCRYPT_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes128_expand_key_x86_avx_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
        unsafe { aes128_encrypt_x86_avx_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.1, block);
        unsafe { aes128_inverse_key_x86_avx_aesni(key_schedule.as_mut_ptr()) };
        unsafe { aes128_decrypt_x86_avx_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.0, block);
      });
    }
  }

  #[test]
  fn test_aes192_encrypt_decrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      let mut key_schedule = [0; 208];
      AES192_ENCRYPT_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes192_expand_key_x86_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
        unsafe { aes192_encrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.1, block);
        unsafe { aes192_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
        unsafe { aes192_decrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.0, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      let mut key_schedule = [0; 208];
      AES192_ENCRYPT_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes192_expand_key_x86_avx_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
        unsafe { aes192_encrypt_x86_avx_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.1, block);
        unsafe { aes192_inverse_key_x86_avx_aesni(key_schedule.as_mut_ptr()) };
        unsafe { aes192_decrypt_x86_avx_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.0, block);
      });
    }
  }

  #[test]
  fn test_aes256_encrypt_decrypt()
  {
    if is_x86_feature_detected!("aes") {
      let mut block = [0; 16];
      let mut key_schedule = [0; 240];
      AES256_ENCRYPT_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes256_expand_key_x86_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
        unsafe { aes256_encrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.1, block);
        unsafe { aes256_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
        unsafe { aes256_decrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.0, block);
      });
    }
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx") {
      let mut block = [0; 16];
      let mut key_schedule = [0; 240];
      AES256_ENCRYPT_DECRYPT.iter().for_each(|t| {
        block = t.0;
        unsafe { aes256_expand_key_x86_avx_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
        unsafe { aes256_encrypt_x86_avx_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.1, block);
        unsafe { aes256_inverse_key_x86_avx_aesni(key_schedule.as_mut_ptr()) };
        unsafe { aes256_decrypt_x86_avx_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
        assert_eq!(t.0, block);
      });
    }
  }
}
