#![allow(clippy::missing_safety_doc)]

#[cfg(all(target_arch = "x86", not(feature = "asm")))]
use core::arch::x86::*;
#[cfg(all(target_arch = "x86_64", not(feature = "asm")))]
use core::arch::x86_64::*;

use cfg_if::cfg_if;

#[inline(always)]
#[cfg(not(feature = "asm"))]
unsafe fn expand_round<const IMM8: i32>(mut k: __m128i, mut kr: __m128i) -> __m128i
{
  kr = _mm_shuffle_epi32::<IMM8>(kr);
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
  _mm_xor_si128(k, kr)
}

#[inline(always)]
pub unsafe fn aes128_expand_key_x86_aesni(key: *const u8, key_schedule: *mut u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        // TODO: find a better way to define macros.
        // AES-128 Expand Round Store x86
        ".ifndef aes128exrsx86_m",
        ".set aes128exrsx86_m, 1",
        ".macro aes128exrsx86 xk, xkr, xtemp, keysched, keyschedoffset, imm",
        "  aeskeygenassist \\xkr, \\xk, \\imm",
        "  pshufd \\xkr,   \\xkr, 0xff",
        "  movdqa \\xtemp, \\xk",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk,    \\xtemp",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk,    \\xtemp",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk,    \\xtemp",
        "  pxor   \\xk,    \\xkr",
        "  movdqu xmmword ptr [\\keysched + \\keyschedoffset], \\xk",
        ".endm",
        ".endif",

        "movdqu {xk}, xmmword ptr [{key}]",
        "movdqu xmmword ptr [{keysched}], {xk}",

        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 16,  0x01",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 32,  0x02",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 48,  0x04",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 64,  0x08",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 80,  0x10",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 96,  0x20",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 112, 0x40",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 128, 0x80",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 144, 0x1b",
        "aes128exrsx86 {xk}, {xkr}, {xtemp}, {keysched}, 160, 0x36",

        key      = in(reg) key,
        keysched = in(reg) key_schedule,

        xk    = out(xmm_reg) _,
        xkr   = out(xmm_reg) _,
        xtemp = out(xmm_reg) _,
      }
    } else {
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
  }
}

#[inline(always)]
pub unsafe fn aes192_expand_key_x86_aesni(key: *const u8, key_schedule: *mut u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        // AES-192 Expand Round x86
        ".ifndef aes192exrx86_m",
        ".set aes192exrx86_m, 1",
        ".macro aes192exrx86 xk0, xk1, xkr, xtemp, imm",
        "  aeskeygenassist \\xkr, \\xk1, \\imm",
        "  pshufd \\xkr,   \\xkr, 0x55",
        "  movdqa \\xtemp, \\xk0",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk0,   \\xtemp",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk0,   \\xtemp",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk0,   \\xtemp",
        "  pxor   \\xk0,   \\xkr",
        ".endm",
        ".endif",
        // AES-192 Expand Round Full x86
        ".ifndef aes192exrfx86_m",
        ".set aes192exrfx86_m, 1",
        ".macro aes192exrfx86 xk0, xk1, xkr, xtemp, imm",
        "  aes192exrx86 \\xk0, \\xk1, \\xkr, \\xtemp, \\imm",
        "  movdqa \\xtemp, \\xk1",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk1,   \\xtemp",
        "  pshufd \\xtemp, \\xk0, 0xff",
        "  pxor   \\xk1,   \\xtemp",
        ".endm",
        ".endif",

        "movdqu {xk0}, xmmword ptr [{key}]",
        "movdqu {xk1}, xmmword ptr [{key} + 8]",
        "psrldq {xk1}, 8",
        "movdqu xmmword ptr [{keysched}],       {xk0}",
        "movdqu xmmword ptr [{keysched} + 16],  {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x01",
        "movdqu xmmword ptr [{keysched} + 24],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 40],  {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x02",
        "movdqu xmmword ptr [{keysched} + 48],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 64],  {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x04",
        "movdqu xmmword ptr [{keysched} + 72],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 88],  {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x08",
        "movdqu xmmword ptr [{keysched} + 96],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 112], {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x10",
        "movdqu xmmword ptr [{keysched} + 120], {xk0}",
        "movdqu xmmword ptr [{keysched} + 136], {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x20",
        "movdqu xmmword ptr [{keysched} + 144], {xk0}",
        "movdqu xmmword ptr [{keysched} + 160], {xk1}",

        "aes192exrfx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x40",
        "movdqu xmmword ptr [{keysched} + 168], {xk0}",
        "movdqu xmmword ptr [{keysched} + 184], {xk1}",

        "aes192exrx86 {xk0}, {xk1}, {xkr}, {xtemp}, 0x80",
        "movdqu xmmword ptr [{keysched} + 192], {xk0}",

        key      = in(reg) key,
        keysched = in(reg) key_schedule,

        xk0   = out(xmm_reg) _,
        xk1   = out(xmm_reg) _,
        xkr   = out(xmm_reg) _,
        xtemp = out(xmm_reg) _,
      }
    } else {
      #[inline(always)]
      unsafe fn expand_round_half(mut k1: __m128i, k0: __m128i) -> __m128i {
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
  }
}

#[inline(always)]
pub unsafe fn aes256_expand_key_x86_aesni(key: *const u8, key_schedule: *mut u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        ".ifndef aes256exrx86_m",
        ".set aes256exrx86_m, 1",
        ".macro aes256exrx86 xk, xkr, xtemp, imm",
        "  pshufd \\xkr,   \\xkr, \\imm",
        "  movdqa \\xtemp, \\xk",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk,    \\xtemp",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk,    \\xtemp",
        "  pslldq \\xtemp, 4",
        "  pxor   \\xk,    \\xtemp",
        "  pxor   \\xk,    \\xkr",
        ".endm",
        ".endif",

        "movdqu {xk0}, xmmword ptr [{key} + 0]",
        "movdqu {xk1}, xmmword ptr [{key} + 16]",
        "movdqu xmmword ptr [{keysched} + 0],   {xk0}",
        "movdqu xmmword ptr [{keysched} + 16],  {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x01",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "aeskeygenassist {xkr}, {xk0}, 0x00",
        "aes256exrx86    {xk1}, {xkr}, {xtemp}, 0xaa",
        "movdqu xmmword ptr [{keysched} + 32],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 48],  {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x02",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "aeskeygenassist {xkr}, {xk0}, 0x00",
        "aes256exrx86    {xk1}, {xkr}, {xtemp}, 0xaa",
        "movdqu xmmword ptr [{keysched} + 64],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 80],  {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x04",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "aeskeygenassist {xkr}, {xk0}, 0x00",
        "aes256exrx86    {xk1}, {xkr}, {xtemp}, 0xaa",
        "movdqu xmmword ptr [{keysched} + 96],  {xk0}",
        "movdqu xmmword ptr [{keysched} + 112], {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x08",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "aeskeygenassist {xkr}, {xk0}, 0x00",
        "aes256exrx86    {xk1}, {xkr}, {xtemp}, 0xaa",
        "movdqu xmmword ptr [{keysched} + 128], {xk0}",
        "movdqu xmmword ptr [{keysched} + 144], {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x10",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "aeskeygenassist {xkr}, {xk0}, 0x00",
        "aes256exrx86    {xk1}, {xkr}, {xtemp}, 0xaa",
        "movdqu xmmword ptr [{keysched} + 160], {xk0}",
        "movdqu xmmword ptr [{keysched} + 176], {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x20",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "aeskeygenassist {xkr}, {xk0}, 0x00",
        "aes256exrx86    {xk1}, {xkr}, {xtemp}, 0xaa",
        "movdqu xmmword ptr [{keysched} + 192], {xk0}",
        "movdqu xmmword ptr [{keysched} + 208], {xk1}",

        "aeskeygenassist {xkr}, {xk1}, 0x40",
        "aes256exrx86    {xk0}, {xkr}, {xtemp}, 0xff",
        "movdqu xmmword ptr [{keysched} + 224], {xk0}",

        key      = in(reg) key,
        keysched = in(reg) key_schedule,

        xk0   = out(xmm_reg) _,
        xk1   = out(xmm_reg) _,
        xkr   = out(xmm_reg) _,
        xtemp = out(xmm_reg) _,
      }
    } else {
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
  }
}

#[inline(always)]
pub unsafe fn aes128_inverse_key_x86_aesni(key_schedule: *mut u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movdqu {xk0}, xmmword ptr [{keysched} + 0]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 160]",
        "movdqu xmmword ptr [{keysched} + 0],   {xk1}",
        "movdqu xmmword ptr [{keysched} + 160], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 16]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 144]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 16],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 144], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 32]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 128]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 32],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 128], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 48]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 112]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 48],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 112], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 64]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 96]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 64], {xk1}",
        "movdqu xmmword ptr [{keysched} + 96], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 80]",
        "aesimc {xk0}, {xk0}",
        "movdqu xmmword ptr [{keysched} + 80], {xk0}",

        keysched = in(reg) key_schedule,

        xk0 = out(xmm_reg) _,
        xk1 = out(xmm_reg) _,
      }
    } else {
      let mut k0: __m128i;
      let mut k1: __m128i;

      k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
      k1 = _mm_loadu_si128((key_schedule as *const __m128i).add(10));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(0), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(10), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(1)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(9)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(1), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(9), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(2)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(8)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(2), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(8), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(3)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(7)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(3), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(7), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(4)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(6)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(4), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(6), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(5)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(5), k0);
    }
  }
}

#[inline(always)]
pub unsafe fn aes192_inverse_key_x86_aesni(key_schedule: *mut u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movdqu {xk0}, xmmword ptr [{keysched} + 0]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 192]",
        "movdqu xmmword ptr [{keysched} + 0],   {xk1}",
        "movdqu xmmword ptr [{keysched} + 192], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 16]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 176]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 16],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 176], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 32]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 160]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 32],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 160], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 48]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 144]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 48],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 144], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 64]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 128]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 64], {xk1}",
        "movdqu xmmword ptr [{keysched} + 128], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 80]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 112]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 80], {xk1}",
        "movdqu xmmword ptr [{keysched} + 112], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 96]",
        "aesimc {xk0}, {xk0}",
        "movdqu xmmword ptr [{keysched} + 96], {xk0}",

        keysched = in(reg) key_schedule,

        xk0 = out(xmm_reg) _,
        xk1 = out(xmm_reg) _,
      }
    } else {
      let mut k0: __m128i;
      let mut k1: __m128i;

      k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
      k1 = _mm_loadu_si128((key_schedule as *const __m128i).add(12));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(0), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(12), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(1)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(11)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(1), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(11), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(2)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(10)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(2), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(10), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(3)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(9)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(3), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(9), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(4)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(8)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(4), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(8), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(5)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(7)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(5), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(7), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(6)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(6), k0);
    }
  }
}

#[inline(always)]
pub unsafe fn aes256_inverse_key_x86_aesni(key_schedule: *mut u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movdqu {xk0}, xmmword ptr [{keysched} + 0]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 224]",
        "movdqu xmmword ptr [{keysched} + 0],   {xk1}",
        "movdqu xmmword ptr [{keysched} + 224], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 16]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 208]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 16],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 208], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 32]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 192]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 32],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 192], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 48]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 176]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 48],  {xk1}",
        "movdqu xmmword ptr [{keysched} + 176], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 64]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 160]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 64], {xk1}",
        "movdqu xmmword ptr [{keysched} + 160], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 80]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 144]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 80], {xk1}",
        "movdqu xmmword ptr [{keysched} + 144], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 96]",
        "movdqu {xk1}, xmmword ptr [{keysched} + 128]",
        "aesimc {xk0}, {xk0}",
        "aesimc {xk1}, {xk1}",
        "movdqu xmmword ptr [{keysched} + 96], {xk1}",
        "movdqu xmmword ptr [{keysched} + 128], {xk0}",

        "movdqu {xk0}, xmmword ptr [{keysched} + 112]",
        "aesimc {xk0}, {xk0}",
        "movdqu xmmword ptr [{keysched} + 112], {xk0}",

        keysched = in(reg) key_schedule,

        xk0 = out(xmm_reg) _,
        xk1 = out(xmm_reg) _,
      }
    } else {
      let mut k0: __m128i;
      let mut k1: __m128i;

      k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
      k1 = _mm_loadu_si128((key_schedule as *const __m128i).add(14));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(0), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(14), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(1)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(13)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(1), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(13), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(2)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(12)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(2), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(12), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(3)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(11)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(3), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(11), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(4)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(10)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(4), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(10), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(5)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(9)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(5), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(9), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(6)));
      k1 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(8)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(6), k1);
      _mm_storeu_si128((key_schedule as *mut __m128i).add(8), k0);

      k0 = _mm_aesimc_si128(_mm_loadu_si128((key_schedule as *const __m128i).add(7)));
      _mm_storeu_si128((key_schedule as *mut __m128i).add(7), k0);
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_encrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movups {xblock}, xmmword ptr [{block}]", // load the block into register
        "movups {xkey},   xmmword ptr [{key}]",   // load the first 16 bytes of the key schedule into
                                                  // register

        "pxor {xblock}, {xkey}", // whitening round (round 0)

        "movups {xkey},   xmmword ptr [{key} + 16]",  // round 1
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 32]",  // round 2
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 48]",  // round 3
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 64]",  // round 4
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 80]",  // round 5
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 96]",  // round 6
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 112]", // round 7
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 128]", // round 8
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 144]", // round 9
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 160]", // round 10
        "aesenclast {xblock}, {xkey}",

        "movups xmmword ptr [{block}], {xblock}",

        block = in(reg) block,
        key   = in(reg) key_schedule,

        xblock = out(xmm_reg) _,
        xkey   = out(xmm_reg) _,
      }
    } else {
      let mut b: __m128i = _mm_loadu_si128(block as *const __m128i);
      let mut k: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

      b = _mm_xor_si128(b, k); // whitening round (round 0)

      k = _mm_loadu_si128((key_schedule as *const __m128i).add(1)); // round 1
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(2)); // round 2
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(3)); // round 3
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(4)); // round 4
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(5)); // round 5
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(6)); // round 6
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(7)); // round 7
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(8)); // round 8
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(9)); // round 9
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(10)); // round 10
      b = _mm_aesenclast_si128(b, k);

      _mm_storeu_si128(block as *mut __m128i, b)
    }
  }
}

#[inline(always)]
pub unsafe fn aes192_encrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movups {xblock}, xmmword ptr [{block}]",
        "movups {xkey},   xmmword ptr [{key}]",

        "pxor {xblock}, {xkey}", // whitening round (round 0)

        "movups {xkey},   xmmword ptr [{key} + 16]",  // round 1
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 32]",  // round 2
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 48]",  // round 3
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 64]",  // round 4
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 80]",  // round 5
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 96]",  // round 6
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 112]", // round 7
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 128]", // round 8
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 144]", // round 9
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 160]", // round 10
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 176]", // round 11
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 192]", // round 12
        "aesenclast {xblock}, {xkey}",

        "movups xmmword ptr [{block}], {xblock}",

        block = in(reg) block,
        key   = in(reg) key_schedule,

        xblock = out(xmm_reg) _,
        xkey   = out(xmm_reg) _,
      }
    } else {
      let mut b: __m128i = _mm_loadu_si128(block as *const __m128i);
      let mut k: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

      b = _mm_xor_si128(b, k); // whitening round (round 0)

      k = _mm_loadu_si128((key_schedule as *const __m128i).add(1)); // round 1
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(2)); // round 2
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(3)); // round 3
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(4)); // round 4
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(5)); // round 5
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(6)); // round 6
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(7)); // round 7
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(8)); // round 8
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(9)); // round 9
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(10)); // round 10
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(11)); // round 11
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(12)); // round 12
      b = _mm_aesenclast_si128(b, k);

      _mm_storeu_si128(block as *mut __m128i, b)
    }
  }
}

#[inline(always)]
pub unsafe fn aes256_encrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movups {xblock}, xmmword ptr [{block}]",
        "movups {xkey},   xmmword ptr [{key}]",

        "pxor {xblock}, {xkey}", // whitening round (round 0)

        "movups {xkey},   xmmword ptr [{key} + 16]",  // round 1
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 32]",  // round 2
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 48]",  // round 3
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 64]",  // round 4
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 80]",  // round 5
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 96]",  // round 6
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 112]", // round 7
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 128]", // round 8
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 144]", // round 9
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 160]", // round 10
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 176]", // round 11
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 192]", // round 12
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 208]", // round 13
        "aesenc {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 224]", // round 14
        "aesenclast {xblock}, {xkey}",

        "movups xmmword ptr [{block}], {xblock}",

        block = in(reg) block,
        key   = in(reg) key_schedule,

        xblock = out(xmm_reg) _,
        xkey   = out(xmm_reg) _,
      }
    } else {
      let mut b: __m128i = _mm_loadu_si128(block as *const __m128i);
      let mut k: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

      b = _mm_xor_si128(b, k); // whitening round (round 0)

      k = _mm_loadu_si128((key_schedule as *const __m128i).add(1)); // round 1
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(2)); // round 2
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(3)); // round 3
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(4)); // round 4
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(5)); // round 5
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(6)); // round 6
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(7)); // round 7
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(8)); // round 8
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(9)); // round 9
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(10)); // round 10
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(11)); // round 11
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(12)); // round 12
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(13)); // round 13
      b = _mm_aesenc_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(14)); // round 14
      b = _mm_aesenclast_si128(b, k);

      _mm_storeu_si128(block as *mut __m128i, b)
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_decrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movups {xblock}, xmmword ptr [{block}]",
        "movups {xkey},   xmmword ptr [{key}]",

        "pxor {xblock}, {xkey}", // round 0

        "movups {xkey},   xmmword ptr [{key} + 16]",  // round 1
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 32]",  // round 2
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 48]",  // round 3
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 64]",  // round 4
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 80]",  // round 5
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 96]",  // round 6
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 112]", // round 7
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 128]", // round 8
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 144]", // round 9
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 160]", // round 10
        "aesdeclast {xblock}, {xkey}",

        "movups xmmword ptr [{block}], {xblock}",

        block = in(reg) block,
        key   = in(reg) key_schedule,

        xblock = out(xmm_reg) _,
        xkey   = out(xmm_reg) _,
      }
    } else {
      let mut b: __m128i = _mm_loadu_si128(block as *const __m128i);
      let mut k: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

      b = _mm_xor_si128(b, k); // round 0

      k = _mm_loadu_si128((key_schedule as *const __m128i).add(1)); // round 1
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(2)); // round 2
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(3)); // round 3
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(4)); // round 4
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(5)); // round 5
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(6)); // round 6
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(7)); // round 7
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(8)); // round 8
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(9)); // round 9
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(10)); // round 10
      b = _mm_aesdeclast_si128(b, k);

      _mm_storeu_si128(block as *mut __m128i, b)
    }
  }
}

#[inline(always)]
pub unsafe fn aes192_decrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movups {xblock}, xmmword ptr [{block}]",
        "movups {xkey},   xmmword ptr [{key}]",

        "pxor {xblock}, {xkey}", // round 0

        "movups {xkey},   xmmword ptr [{key} + 16]",  // round 1
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 32]",  // round 2
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 48]",  // round 3
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 64]",  // round 4
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 80]",  // round 5
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 96]",  // round 6
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 112]", // round 7
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 128]", // round 8
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 144]", // round 9
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 160]", // round 10
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 176]", // round 11
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 192]", // round 12
        "aesdeclast {xblock}, {xkey}",

        "movups xmmword ptr [{block}], {xblock}",

        block = in(reg) block,
        key   = in(reg) key_schedule,

        xblock = out(xmm_reg) _,
        xkey   = out(xmm_reg) _,
      }
    } else {
      let mut b: __m128i = _mm_loadu_si128(block as *const __m128i);
      let mut k: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

      b = _mm_xor_si128(b, k); // round 0

      k = _mm_loadu_si128((key_schedule as *const __m128i).add(1)); // round 1
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(2)); // round 2
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(3)); // round 3
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(4)); // round 4
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(5)); // round 5
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(6)); // round 6
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(7)); // round 7
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(8)); // round 8
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(9)); // round 9
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(10)); // round 10
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(11)); // round 11
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(12)); // round 12
      b = _mm_aesdeclast_si128(b, k);

      _mm_storeu_si128(block as *mut __m128i, b)
    }
  }
}

#[inline(always)]
pub unsafe fn aes256_decrypt_x86_aesni(block: *mut u8, key_schedule: *const u8)
{
  cfg_if! {
    if #[cfg(feature = "asm")] {
      asm! {
        "movups {xblock}, xmmword ptr [{block}]",
        "movups {xkey},   xmmword ptr [{key}]",

        "pxor {xblock}, {xkey}", // round 0

        "movups {xkey},   xmmword ptr [{key} + 16]",  // round 1
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 32]",  // round 2
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 48]",  // round 3
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 64]",  // round 4
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 80]",  // round 5
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 96]",  // round 6
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 112]", // round 7
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 128]", // round 8
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 144]", // round 9
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 160]", // round 10
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 176]", // round 11
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 192]", // round 12
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 208]", // round 13
        "aesdec {xblock}, {xkey}",
        "movups {xkey},   xmmword ptr [{key} + 224]", // round 14
        "aesdeclast {xblock}, {xkey}",

        "movups xmmword ptr [{block}], {xblock}",

        block = in(reg) block,
        key   = in(reg) key_schedule,

        xblock = out(xmm_reg) _,
        xkey   = out(xmm_reg) _,
      }
    } else {
      let mut b: __m128i = _mm_loadu_si128(block as *const __m128i);
      let mut k: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));

      b = _mm_xor_si128(b, k); // round 0

      k = _mm_loadu_si128((key_schedule as *const __m128i).add(1)); // round 1
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(2)); // round 2
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(3)); // round 3
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(4)); // round 4
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(5)); // round 5
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(6)); // round 6
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(7)); // round 7
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(8)); // round 8
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(9)); // round 9
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(10)); // round 10
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(11)); // round 11
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(12)); // round 12
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(13)); // round 13
      b = _mm_aesdec_si128(b, k);
      k = _mm_loadu_si128((key_schedule as *const __m128i).add(14)); // round 14
      b = _mm_aesdeclast_si128(b, k);

      _mm_storeu_si128(block as *mut __m128i, b)
    }
  }
}

#[cfg(test)]
mod tests
{
  extern crate std;

  use super::*;

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes128_expand_key()
  {
    let tests: &[([u8; 16], [u8; 176])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes128-expand-key.txt"
    ));
    let mut key_schedule = [0; 176];
    tests.iter().for_each(|t| {
      unsafe { aes128_expand_key_x86_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes192_expand_key()
  {
    let tests: &[([u8; 24], [u8; 208])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes192-expand-key.txt"
    ));
    let mut key_schedule = [0; 208];
    tests.iter().for_each(|t| {
      unsafe { aes192_expand_key_x86_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes256_expand_key()
  {
    let tests: &[([u8; 32], [u8; 240])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes256-expand-key.txt"
    ));
    let mut key_schedule = [0; 240];
    tests.iter().for_each(|t| {
      unsafe { aes256_expand_key_x86_aesni(t.0.as_ptr(), key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes128_inverse_key()
  {
    let tests: &[([u8; 176], [u8; 176])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes128-inverse-key.txt"
    ));
    let mut key_schedule = [0; 176];
    tests.iter().for_each(|t| {
      key_schedule = t.0;
      unsafe { aes128_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes192_inverse_key()
  {
    let tests: &[([u8; 208], [u8; 208])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes192-inverse-key.txt"
    ));
    let mut key_schedule = [0; 208];
    tests.iter().for_each(|t| {
      key_schedule = t.0;
      unsafe { aes192_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes256_inverse_key()
  {
    let tests: &[([u8; 240], [u8; 240])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes256-inverse-key.txt"
    ));
    let mut key_schedule = [0; 240];
    tests.iter().for_each(|t| {
      key_schedule = t.0;
      unsafe { aes256_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
      assert_eq!(t.1, key_schedule);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes128_encrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 176])] =
      &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes128-encrypt.txt"));
    let mut block = [0; 16];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes128_encrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes192_encrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 208])] =
      &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes192-encrypt.txt"));
    let mut block = [0; 16];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes192_encrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes256_encrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 240])] =
      &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes256-encrypt.txt"));
    let mut block = [0; 16];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes256_encrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes128_decrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 176])] =
      &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes128-decrypt.txt"));
    let mut block = [0; 16];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes128_decrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes192_decrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 208])] =
      &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes192-decrypt.txt"));
    let mut block = [0; 16];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes192_decrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes256_decrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 240])] =
      &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/aes256-decrypt.txt"));
    let mut block = [0; 16];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes256_decrypt_x86_aesni(block.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes128_encrypt_decrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 16])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes128-encrypt-decrypt.txt"
    ));
    let mut block = [0; 16];
    let mut key_schedule = [0; 176];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes128_expand_key_x86_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
      unsafe { aes128_encrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.1, block);
      unsafe { aes128_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
      unsafe { aes128_decrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.0, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes192_encrypt_decrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 24])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes192-encrypt-decrypt.txt"
    ));
    let mut block = [0; 16];
    let mut key_schedule = [0; 208];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes192_expand_key_x86_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
      unsafe { aes192_encrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.1, block);
      unsafe { aes192_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
      unsafe { aes192_decrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.0, block);
    });
  }

  #[test]
  #[cfg_attr(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    ignore
  )]
  fn test_aes256_encrypt_decrypt()
  {
    let tests: &[([u8; 16], [u8; 16], [u8; 32])] = &include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/test-vectors/aes256-encrypt-decrypt.txt"
    ));
    let mut block = [0; 16];
    let mut key_schedule = [0; 240];
    tests.iter().for_each(|t| {
      block = t.0;
      unsafe { aes256_expand_key_x86_aesni(t.2.as_ptr(), key_schedule.as_mut_ptr()) };
      unsafe { aes256_encrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.1, block);
      unsafe { aes256_inverse_key_x86_aesni(key_schedule.as_mut_ptr()) };
      unsafe { aes256_decrypt_x86_aesni(block.as_mut_ptr(), key_schedule.as_ptr()) };
      assert_eq!(t.0, block);
    });
  }
}
