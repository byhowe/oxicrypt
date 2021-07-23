#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("This module is only available in x86");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn expand_round<const IMM8: i32>(mut k: __m128i, mut kr: __m128i) -> __m128i
{
  kr = _mm_shuffle_epi32::<IMM8>(kr);
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  _mm_xor_si128(k, kr)
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_expand_key(key: *const u8, key_schedule: *mut u8)
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

#[target_feature(enable = "aes")]
pub unsafe fn aes192_expand_key(key: *const u8, key_schedule: *mut u8)
{
  #[inline(always)]
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

#[target_feature(enable = "aes")]
pub unsafe fn aes256_expand_key(key: *const u8, key_schedule: *mut u8)
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

#[target_feature(enable = "aes")]
pub unsafe fn aes128_inverse_key(key_schedule: *mut u8)
{
  aes_inverse_key::<10>(key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_inverse_key(key_schedule: *mut u8)
{
  aes_inverse_key::<12>(key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_inverse_key(key_schedule: *mut u8)
{
  aes_inverse_key::<14>(key_schedule);
}

#[inline(always)]
unsafe fn aes_encrypt1<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));

  b0 = _mm_xor_si128(b0, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
}

#[inline(always)]
unsafe fn aes_encrypt2<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
    b1 = _mm_aesenc_si128(b1, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);
  b1 = _mm_aesenclast_si128(b1, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
}

#[inline(always)]
unsafe fn aes_encrypt4<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));
  let mut b2: __m128i = _mm_loadu_si128((block as *const __m128i).add(2));
  let mut b3: __m128i = _mm_loadu_si128((block as *const __m128i).add(3));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);
  b2 = _mm_xor_si128(b2, k0);
  b3 = _mm_xor_si128(b3, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
    b1 = _mm_aesenc_si128(b1, k0);
    b2 = _mm_aesenc_si128(b2, k0);
    b3 = _mm_aesenc_si128(b3, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);
  b1 = _mm_aesenclast_si128(b1, k0);
  b2 = _mm_aesenclast_si128(b2, k0);
  b3 = _mm_aesenclast_si128(b3, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
}

#[inline(always)]
unsafe fn aes_encrypt8<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));
  let mut b2: __m128i = _mm_loadu_si128((block as *const __m128i).add(2));
  let mut b3: __m128i = _mm_loadu_si128((block as *const __m128i).add(3));
  let mut b4: __m128i = _mm_loadu_si128((block as *const __m128i).add(4));
  let mut b5: __m128i = _mm_loadu_si128((block as *const __m128i).add(5));
  let mut b6: __m128i = _mm_loadu_si128((block as *const __m128i).add(6));
  let mut b7: __m128i = _mm_loadu_si128((block as *const __m128i).add(7));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);
  b2 = _mm_xor_si128(b2, k0);
  b3 = _mm_xor_si128(b3, k0);
  b4 = _mm_xor_si128(b4, k0);
  b5 = _mm_xor_si128(b5, k0);
  b6 = _mm_xor_si128(b6, k0);
  b7 = _mm_xor_si128(b7, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
    b1 = _mm_aesenc_si128(b1, k0);
    b2 = _mm_aesenc_si128(b2, k0);
    b3 = _mm_aesenc_si128(b3, k0);
    b4 = _mm_aesenc_si128(b4, k0);
    b5 = _mm_aesenc_si128(b5, k0);
    b6 = _mm_aesenc_si128(b6, k0);
    b7 = _mm_aesenc_si128(b7, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);
  b1 = _mm_aesenclast_si128(b1, k0);
  b2 = _mm_aesenclast_si128(b2, k0);
  b3 = _mm_aesenclast_si128(b3, k0);
  b4 = _mm_aesenclast_si128(b4, k0);
  b5 = _mm_aesenclast_si128(b5, k0);
  b6 = _mm_aesenclast_si128(b6, k0);
  b7 = _mm_aesenclast_si128(b7, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
  _mm_storeu_si128((block as *mut __m128i).add(4), b4);
  _mm_storeu_si128((block as *mut __m128i).add(5), b5);
  _mm_storeu_si128((block as *mut __m128i).add(6), b6);
  _mm_storeu_si128((block as *mut __m128i).add(7), b7);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt1::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt1::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt1::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt2::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt2::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt2::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt4::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt4::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt4::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt8::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt8::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_encrypt8::<14>(block, key_schedule);
}

#[inline(always)]
unsafe fn aes_decrypt1<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));

  b0 = _mm_xor_si128(b0, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
}

#[inline(always)]
unsafe fn aes_decrypt2<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
    b1 = _mm_aesdec_si128(b1, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);
  b1 = _mm_aesdeclast_si128(b1, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
}

#[inline(always)]
unsafe fn aes_decrypt4<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));
  let mut b2: __m128i = _mm_loadu_si128((block as *const __m128i).add(2));
  let mut b3: __m128i = _mm_loadu_si128((block as *const __m128i).add(3));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);
  b2 = _mm_xor_si128(b2, k0);
  b3 = _mm_xor_si128(b3, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
    b1 = _mm_aesdec_si128(b1, k0);
    b2 = _mm_aesdec_si128(b2, k0);
    b3 = _mm_aesdec_si128(b3, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);
  b1 = _mm_aesdeclast_si128(b1, k0);
  b2 = _mm_aesdeclast_si128(b2, k0);
  b3 = _mm_aesdeclast_si128(b3, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
}

#[inline(always)]
unsafe fn aes_decrypt8<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));
  let mut b2: __m128i = _mm_loadu_si128((block as *const __m128i).add(2));
  let mut b3: __m128i = _mm_loadu_si128((block as *const __m128i).add(3));
  let mut b4: __m128i = _mm_loadu_si128((block as *const __m128i).add(4));
  let mut b5: __m128i = _mm_loadu_si128((block as *const __m128i).add(5));
  let mut b6: __m128i = _mm_loadu_si128((block as *const __m128i).add(6));
  let mut b7: __m128i = _mm_loadu_si128((block as *const __m128i).add(7));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);
  b2 = _mm_xor_si128(b2, k0);
  b3 = _mm_xor_si128(b3, k0);
  b4 = _mm_xor_si128(b4, k0);
  b5 = _mm_xor_si128(b5, k0);
  b6 = _mm_xor_si128(b6, k0);
  b7 = _mm_xor_si128(b7, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
    b1 = _mm_aesdec_si128(b1, k0);
    b2 = _mm_aesdec_si128(b2, k0);
    b3 = _mm_aesdec_si128(b3, k0);
    b4 = _mm_aesdec_si128(b4, k0);
    b5 = _mm_aesdec_si128(b5, k0);
    b6 = _mm_aesdec_si128(b6, k0);
    b7 = _mm_aesdec_si128(b7, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);
  b1 = _mm_aesdeclast_si128(b1, k0);
  b2 = _mm_aesdeclast_si128(b2, k0);
  b3 = _mm_aesdeclast_si128(b3, k0);
  b4 = _mm_aesdeclast_si128(b4, k0);
  b5 = _mm_aesdeclast_si128(b5, k0);
  b6 = _mm_aesdeclast_si128(b6, k0);
  b7 = _mm_aesdeclast_si128(b7, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
  _mm_storeu_si128((block as *mut __m128i).add(4), b4);
  _mm_storeu_si128((block as *mut __m128i).add(5), b5);
  _mm_storeu_si128((block as *mut __m128i).add(6), b6);
  _mm_storeu_si128((block as *mut __m128i).add(7), b7);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt1::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt1::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt1::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt2::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt2::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt2::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt4::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt4::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt4::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt8::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes192_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt8::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
pub unsafe fn aes256_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt8::<14>(block, key_schedule);
}

#[cfg(test)]
mod tests
{
  use std_detect::is_x86_feature_detected;

  use super::*;
  use crate::aes::Variant;
  use crate::test_vectors::*;

  #[test]
  fn test_expand_key()
  {
    if is_x86_feature_detected!("aes") {
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
  }

  #[test]
  fn test_inverse_key()
  {
    if is_x86_feature_detected!("aes") {
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
  }

  #[inline(always)]
  fn test_encrypt<const N: usize, const A: usize>(
    e128: unsafe fn(*mut u8, *const u8),
    e192: unsafe fn(*mut u8, *const u8),
    e256: unsafe fn(*mut u8, *const u8),
  )
  {
    if is_x86_feature_detected!("aes") {
      AES128_ENCRYPT.iter().for_each(|t| {
        let mut block = [0; A];
        for i in 0 .. N {
          block[i * 16 .. i * 16 + 16].copy_from_slice(&t.0);
        }
        unsafe { e128(block.as_mut_ptr(), t.2.as_ptr()) };
        for i in 0 .. N {
          assert_eq!(t.1, block[i * 16 .. i * 16 + 16]);
        }
      });
      AES192_ENCRYPT.iter().for_each(|t| {
        let mut block = [0; A];
        for i in 0 .. N {
          block[i * 16 .. i * 16 + 16].copy_from_slice(&t.0);
        }
        unsafe { e192(block.as_mut_ptr(), t.2.as_ptr()) };
        for i in 0 .. N {
          assert_eq!(t.1, block[i * 16 .. i * 16 + 16]);
        }
      });
      AES256_ENCRYPT.iter().for_each(|t| {
        let mut block = [0; A];
        for i in 0 .. N {
          block[i * 16 .. i * 16 + 16].copy_from_slice(&t.0);
        }
        unsafe { e256(block.as_mut_ptr(), t.2.as_ptr()) };
        for i in 0 .. N {
          assert_eq!(t.1, block[i * 16 .. i * 16 + 16]);
        }
      });
    }
  }

  #[test]
  fn test_encrypt1()
  {
    test_encrypt::<1, 16>(aes128_encrypt1, aes192_encrypt1, aes256_encrypt1);
  }

  #[test]
  fn test_encrypt2()
  {
    test_encrypt::<2, 32>(aes128_encrypt2, aes192_encrypt2, aes256_encrypt2);
  }

  #[test]
  fn test_encrypt4()
  {
    test_encrypt::<4, 64>(aes128_encrypt4, aes192_encrypt4, aes256_encrypt4);
  }

  #[test]
  fn test_encrypt8()
  {
    test_encrypt::<8, 128>(aes128_encrypt8, aes192_encrypt8, aes256_encrypt8);
  }

  #[inline(always)]
  fn test_decrypt<const N: usize, const A: usize>(
    d128: unsafe fn(*mut u8, *const u8),
    d192: unsafe fn(*mut u8, *const u8),
    d256: unsafe fn(*mut u8, *const u8),
  )
  {
    if is_x86_feature_detected!("aes") {
      AES128_DECRYPT.iter().for_each(|t| {
        let mut block = [0; A];
        for i in 0 .. N {
          block[i * 16 .. i * 16 + 16].copy_from_slice(&t.0);
        }
        unsafe { d128(block.as_mut_ptr(), t.2.as_ptr()) };
        for i in 0 .. N {
          assert_eq!(t.1, block[i * 16 .. i * 16 + 16]);
        }
      });
      AES192_DECRYPT.iter().for_each(|t| {
        let mut block = [0; A];
        for i in 0 .. N {
          block[i * 16 .. i * 16 + 16].copy_from_slice(&t.0);
        }
        unsafe { d192(block.as_mut_ptr(), t.2.as_ptr()) };
        for i in 0 .. N {
          assert_eq!(t.1, block[i * 16 .. i * 16 + 16]);
        }
      });
      AES256_DECRYPT.iter().for_each(|t| {
        let mut block = [0; A];
        for i in 0 .. N {
          block[i * 16 .. i * 16 + 16].copy_from_slice(&t.0);
        }
        unsafe { d256(block.as_mut_ptr(), t.2.as_ptr()) };
        for i in 0 .. N {
          assert_eq!(t.1, block[i * 16 .. i * 16 + 16]);
        }
      });
    }
  }

  #[test]
  fn test_decrypt1()
  {
    test_decrypt::<1, 16>(aes128_decrypt1, aes192_decrypt1, aes256_decrypt1);
  }

  #[test]
  fn test_decrypt2()
  {
    test_decrypt::<2, 32>(aes128_decrypt2, aes192_decrypt2, aes256_decrypt2);
  }

  #[test]
  fn test_decrypt4()
  {
    test_decrypt::<4, 64>(aes128_decrypt4, aes192_decrypt4, aes256_decrypt4);
  }

  #[test]
  fn test_decrypt8()
  {
    test_decrypt::<8, 128>(aes128_decrypt8, aes192_decrypt8, aes256_decrypt8);
  }

  #[test]
  fn test_encrypt_decrypt()
  {
    if is_x86_feature_detected!("aes") {
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
}
