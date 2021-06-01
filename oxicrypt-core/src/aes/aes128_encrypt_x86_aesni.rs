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
//       A: Yes.
// TODO: Q: Is it actually faster than the Rust implementation?
//       A: Seems to be approximately 1.8 times faster than the Rust implementation using the
//          core::arch::* functions for AES-NI.
#[inline(always)]
pub unsafe fn aes128_encrypt_x86_aesni(block: *mut u8, round_keys: *const u8)
{
  asm! {
    // Copy the block into xmm0 register.
    "movups xmm0, xmmword ptr [{block}]",
    // Copy the first 16 bytes of the key (k00) into the xmm1 register.
    "movups xmm1, xmmword ptr [{key}]",

    // Xor the block with k00.
    "xorps xmm0, xmm1",

    // Copy the next bytes of the key into xmm1 register and perform the whole aesenc sequence.
    "movups xmm1, xmmword ptr [{key} + 16]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 32]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 48]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 64]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 80]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 96]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 112]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 128]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 144]",
    "aesenc xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 160]",
    "aesenclast xmm0, xmm1",

    // Copy the resulting block back into the passed pointer.
    "movups xmmword ptr [{block}], xmm0",

    block = in(reg) block,
    key = in(reg) round_keys,

    // I am not sure if these do anything.
    out("xmm0") _,
    out("xmm1") _,
  }
}
