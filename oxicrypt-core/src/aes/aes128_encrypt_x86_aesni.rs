#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

macro_rules! aes_enc_8_rounds {
  ($b0:ident, $b1:ident, $b2:ident, $b3:ident, $b4:ident, $b5:ident, $b6:ident, $b7:ident, $k:ident) => {
    $b0 = _mm_aesenc_si128($b0, $k);
    $b1 = _mm_aesenc_si128($b1, $k);
    $b2 = _mm_aesenc_si128($b2, $k);
    $b3 = _mm_aesenc_si128($b3, $k);
    $b4 = _mm_aesenc_si128($b4, $k);
    $b5 = _mm_aesenc_si128($b5, $k);
    $b6 = _mm_aesenc_si128($b6, $k);
    $b7 = _mm_aesenc_si128($b7, $k);
  };
}

macro_rules! aes_enc_last_8_rounds {
  ($b0:ident, $b1:ident, $b2:ident, $b3:ident, $b4:ident, $b5:ident, $b6:ident, $b7:ident, $k:ident) => {
    $b0 = _mm_aesenclast_si128($b0, $k);
    $b1 = _mm_aesenclast_si128($b1, $k);
    $b2 = _mm_aesenclast_si128($b2, $k);
    $b3 = _mm_aesenclast_si128($b3, $k);
    $b4 = _mm_aesenclast_si128($b4, $k);
    $b5 = _mm_aesenclast_si128($b5, $k);
    $b6 = _mm_aesenclast_si128($b6, $k);
    $b7 = _mm_aesenclast_si128($b7, $k);
  };
}

macro_rules! aes_expand_round {
  ($k:ident, $round:expr) => {{
    let mut k = $k;
    let t1 = _mm_shuffle_epi32(_mm_aeskeygenassist_si128($k, $round), 0xff);
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

#[inline(always)]
pub unsafe fn aes128_encrypt_x86_aesni(block: *mut u8, round_keys: *const u8)
{
  let k00: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(0));
  let k01: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(1));
  let k02: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(2));
  let k03: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(3));
  let k04: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(4));
  let k05: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(5));
  let k06: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(6));
  let k07: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(7));
  let k08: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(8));
  let k09: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(9));
  let k10: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(10));
  let mut b = _mm_loadu_si128(block as *const __m128i);
  b = _mm_xor_si128(b, k00);
  b = _mm_aesenc_si128(b, k01);
  b = _mm_aesenc_si128(b, k02);
  b = _mm_aesenc_si128(b, k03);
  b = _mm_aesenc_si128(b, k04);
  b = _mm_aesenc_si128(b, k05);
  b = _mm_aesenc_si128(b, k06);
  b = _mm_aesenc_si128(b, k07);
  b = _mm_aesenc_si128(b, k08);
  b = _mm_aesenc_si128(b, k09);
  b = _mm_aesenclast_si128(b, k10);
  _mm_storeu_si128(block as *mut __m128i, b)
}

#[inline(always)]
pub unsafe fn aes128_encrypt8_x86_aesni(blocks: *mut u8, round_keys: *const u8)
{
  let k00: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(0));
  let k01: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(1));
  let k02: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(2));
  let k03: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(3));
  let k04: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(4));
  let k05: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(5));
  let k06: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(6));
  let k07: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(7));
  let k08: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(8));
  let k09: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(9));
  let k10: __m128i = _mm_loadu_si128((round_keys as *const __m128i).add(10));
  let mut b0 = _mm_loadu_si128((blocks as *const __m128i).add(0));
  let mut b1 = _mm_loadu_si128((blocks as *const __m128i).add(1));
  let mut b2 = _mm_loadu_si128((blocks as *const __m128i).add(2));
  let mut b3 = _mm_loadu_si128((blocks as *const __m128i).add(3));
  let mut b4 = _mm_loadu_si128((blocks as *const __m128i).add(4));
  let mut b5 = _mm_loadu_si128((blocks as *const __m128i).add(5));
  let mut b6 = _mm_loadu_si128((blocks as *const __m128i).add(6));
  let mut b7 = _mm_loadu_si128((blocks as *const __m128i).add(7));
  b0 = _mm_xor_si128(b0, k00);
  b1 = _mm_xor_si128(b1, k00);
  b2 = _mm_xor_si128(b2, k00);
  b3 = _mm_xor_si128(b3, k00);
  b4 = _mm_xor_si128(b4, k00);
  b5 = _mm_xor_si128(b5, k00);
  b6 = _mm_xor_si128(b6, k00);
  b7 = _mm_xor_si128(b7, k00);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k01);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k02);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k03);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k04);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k05);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k06);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k07);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k08);
  aes_enc_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k09);
  aes_enc_last_8_rounds!(b0, b1, b2, b3, b4, b5, b6, b7, k10);
  _mm_storeu_si128((blocks as *mut __m128i).add(0), b0);
  _mm_storeu_si128((blocks as *mut __m128i).add(1), b1);
  _mm_storeu_si128((blocks as *mut __m128i).add(2), b2);
  _mm_storeu_si128((blocks as *mut __m128i).add(3), b3);
  _mm_storeu_si128((blocks as *mut __m128i).add(4), b4);
  _mm_storeu_si128((blocks as *mut __m128i).add(5), b5);
  _mm_storeu_si128((blocks as *mut __m128i).add(6), b6);
  _mm_storeu_si128((blocks as *mut __m128i).add(7), b7);
}
