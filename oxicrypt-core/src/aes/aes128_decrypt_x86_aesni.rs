#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

macro_rules! aes_expand_round {
  ($k:ident, $round:expr) => {{
    let mut k = $k;
    let t1 = _mm_shuffle_epi32(_mm_aeskeygenassist_si128($k, $round), _MM_SHUFFLE(3, 3, 3, 3));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    _mm_xor_si128(k, t1)
  }};
}

#[inline(always)]
pub unsafe fn aes128_expand_decrypt_key_x86_aesni(key: *const u8, round_keys: *mut u8)
{
  let k00: __m128i = _mm_loadu_si128(key as *const __m128i);
  let k01: __m128i = aes_expand_round!(k00, 0x01);
  let k02: __m128i = aes_expand_round!(k01, 0x02);
  let k03: __m128i = aes_expand_round!(k02, 0x04);
  let k04: __m128i = aes_expand_round!(k03, 0x08);
  let k05: __m128i = aes_expand_round!(k04, 0x10);
  let k06: __m128i = aes_expand_round!(k05, 0x20);
  let k07: __m128i = aes_expand_round!(k06, 0x40);
  let k08: __m128i = aes_expand_round!(k07, 0x80);
  let k09: __m128i = aes_expand_round!(k08, 0x1B);
  let k10: __m128i = aes_expand_round!(k09, 0x36);
  _mm_storeu_si128((round_keys as *mut __m128i).add(0), k10);
  _mm_storeu_si128((round_keys as *mut __m128i).add(1), _mm_aesimc_si128(k09));
  _mm_storeu_si128((round_keys as *mut __m128i).add(2), _mm_aesimc_si128(k08));
  _mm_storeu_si128((round_keys as *mut __m128i).add(3), _mm_aesimc_si128(k07));
  _mm_storeu_si128((round_keys as *mut __m128i).add(4), _mm_aesimc_si128(k06));
  _mm_storeu_si128((round_keys as *mut __m128i).add(5), _mm_aesimc_si128(k05));
  _mm_storeu_si128((round_keys as *mut __m128i).add(6), _mm_aesimc_si128(k04));
  _mm_storeu_si128((round_keys as *mut __m128i).add(7), _mm_aesimc_si128(k03));
  _mm_storeu_si128((round_keys as *mut __m128i).add(8), _mm_aesimc_si128(k02));
  _mm_storeu_si128((round_keys as *mut __m128i).add(9), _mm_aesimc_si128(k01));
  _mm_storeu_si128((round_keys as *mut __m128i).add(10), k00);
}

#[inline(always)]
pub unsafe fn aes128_decrypt_x86_aesni(block: *mut u8, round_keys: *const u8)
{
  asm! {
    "movdqa     xmm0,  xmmword ptr [{0}]", // Move the 16 bytes stored in block to the xmm0 register.
    "movups     xmm1,  xmmword ptr [{1}]", // Move the round keys to their respective registers.
    "movups     xmm2,  xmmword ptr [{1} + 16]",
    "movups     xmm3,  xmmword ptr [{1} + 32]",
    "movups     xmm4,  xmmword ptr [{1} + 48]",
    "movups     xmm5,  xmmword ptr [{1} + 64]",
    "movups     xmm6,  xmmword ptr [{1} + 80]",
    "movups     xmm7,  xmmword ptr [{1} + 96]",
    "movups     xmm8,  xmmword ptr [{1} + 112]",
    "movups     xmm9,  xmmword ptr [{1} + 128]",
    "movups     xmm10, xmmword ptr [{1} + 144]",
    "movups     xmm11, xmmword ptr [{1} + 160]",
    "xorps      xmm0,  xmm1", // Perform xor between xmm0 and xmm1, then store the result in xmm0.
    "aesdec     xmm0,  xmm2", // Perform aes encryption.
    "aesdec     xmm0,  xmm3",
    "aesdec     xmm0,  xmm4",
    "aesdec     xmm0,  xmm5",
    "aesdec     xmm0,  xmm6",
    "aesdec     xmm0,  xmm7",
    "aesdec     xmm0,  xmm8",
    "aesdec     xmm0,  xmm9",
    "aesdec     xmm0,  xmm10",
    "aesdeclast xmm0,  xmm11",
    "movdqu     xmmword ptr [{0}], xmm0", // Store the computed result back into block.
    in(reg) block,
    in(reg) round_keys,
  }
}
