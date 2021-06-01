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
    // Copy the block into xmm0 register.
    "movups xmm0, xmmword ptr [{block}]",
    // Copy the first 16 bytes of the key (k00) into the xmm1 register.
    "movups xmm1, xmmword ptr [{key}]",

    // Xor the block with k00.
    "xorps xmm0, xmm1",

    // Copy the next bytes of the key into xmm1 register and perform the whole aesdec sequence.
    "movups xmm1, xmmword ptr [{key} + 16]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 32]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 48]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 64]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 80]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 96]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 112]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 128]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 144]",
    "aesdec xmm0, xmm1",
    "movups xmm1, xmmword ptr [{key} + 160]",
    "aesdeclast xmm0, xmm1",

    // Copy the resulting block back into the passed pointer.
    "movups xmmword ptr [{block}], xmm0",

    block = in(reg) block,
    key = in(reg) round_keys,

    // I am not sure if these do anything.
    out("xmm0") _,
    out("xmm1") _,
  }
}
