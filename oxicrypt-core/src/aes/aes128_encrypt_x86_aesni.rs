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
pub unsafe fn aes128_expand_encrypt_key_x86_aesni(key: *const u8, round_keys: *mut u8)
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
  _mm_storeu_si128((round_keys as *mut __m128i).add(0), k00);
  _mm_storeu_si128((round_keys as *mut __m128i).add(1), k01);
  _mm_storeu_si128((round_keys as *mut __m128i).add(2), k02);
  _mm_storeu_si128((round_keys as *mut __m128i).add(3), k03);
  _mm_storeu_si128((round_keys as *mut __m128i).add(4), k04);
  _mm_storeu_si128((round_keys as *mut __m128i).add(5), k05);
  _mm_storeu_si128((round_keys as *mut __m128i).add(6), k06);
  _mm_storeu_si128((round_keys as *mut __m128i).add(7), k07);
  _mm_storeu_si128((round_keys as *mut __m128i).add(8), k08);
  _mm_storeu_si128((round_keys as *mut __m128i).add(9), k09);
  _mm_storeu_si128((round_keys as *mut __m128i).add(10), k10);
}

// I decided to write this function in assembly with my limited assembly knowledge. I think i
// succeeded, but i am not responsible if your PC blows up in flames.
// TODO: Q: Does this work on x86?
// TODO: Q: Is it actually faster than the Rust implementation?
#[inline(always)]
pub unsafe fn aes128_encrypt_x86_aesni(block: *mut u8, round_keys: *const u8)
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
    "xorps      xmm0,  xmm1", // Perform xor between xmm0 and xmm1, then store the result in xmm0.
    "aesenc     xmm0,  xmm2", // Perform aes encryption.
    "aesenc     xmm0,  xmm3",
    "aesenc     xmm0,  xmm4",
    "aesenc     xmm0,  xmm5",
    "aesenc     xmm0,  xmm6",
    "aesenc     xmm0,  xmm7",
    "movups     xmm1,  xmmword ptr [{1} + 112]",
    "movups     xmm2,  xmmword ptr [{1} + 128]",
    "movups     xmm3,  xmmword ptr [{1} + 144]",
    "movups     xmm4,  xmmword ptr [{1} + 160]",
    "aesenc     xmm0,  xmm1",
    "aesenc     xmm0,  xmm2",
    "aesenc     xmm0,  xmm3",
    "aesenclast xmm0,  xmm4",
    "movdqu     xmmword ptr [{0}], xmm0", // Store the computed result back into block.
    in(reg) block,
    in(reg) round_keys,
  }
}
