#[allow(clippy::many_single_char_names)]
#[inline(always)]
const fn choose(mask: u32, a: u32, b: u32) -> u32
{
  b ^ (mask & (a ^ b))
}

#[allow(clippy::many_single_char_names)]
#[inline(always)]
const fn ff<const S: u32>(a: u32, b: u32, c: u32, d: u32, w: u32, rc: u32) -> u32
{
  choose(b, c, d)
    .wrapping_add(a)
    .wrapping_add(w)
    .wrapping_add(rc)
    .rotate_left(S)
    .wrapping_add(b)
}

#[allow(clippy::many_single_char_names)]
#[inline(always)]
const fn gg<const S: u32>(a: u32, b: u32, c: u32, d: u32, w: u32, rc: u32) -> u32
{
  choose(d, b, c)
    .wrapping_add(a)
    .wrapping_add(w)
    .wrapping_add(rc)
    .rotate_left(S)
    .wrapping_add(b)
}

#[allow(clippy::many_single_char_names)]
#[inline(always)]
const fn hh<const S: u32>(a: u32, b: u32, c: u32, d: u32, w: u32, rc: u32) -> u32
{
  (b ^ c ^ d)
    .wrapping_add(a)
    .wrapping_add(w)
    .wrapping_add(rc)
    .rotate_left(S)
    .wrapping_add(b)
}

#[allow(clippy::many_single_char_names)]
#[inline(always)]
const fn ii<const S: u32>(a: u32, b: u32, c: u32, d: u32, w: u32, rc: u32) -> u32
{
  (c ^ (b | !d))
    .wrapping_add(a)
    .wrapping_add(w)
    .wrapping_add(rc)
    .rotate_left(S)
    .wrapping_add(b)
}

#[allow(clippy::many_single_char_names)]
#[allow(unused_assignments)]
pub const unsafe fn md5_compress_generic(state: *mut u32, block: *const u8)
{
  let mut a: u32 = *state.add(0);
  let mut b: u32 = *state.add(1);
  let mut c: u32 = *state.add(2);
  let mut d: u32 = *state.add(3);

  let w00: u32 = (*(block as *const u32).add(0)).to_le();
  let w01: u32 = (*(block as *const u32).add(1)).to_le();
  let w02: u32 = (*(block as *const u32).add(2)).to_le();
  let w03: u32 = (*(block as *const u32).add(3)).to_le();
  let w04: u32 = (*(block as *const u32).add(4)).to_le();
  let w05: u32 = (*(block as *const u32).add(5)).to_le();
  let w06: u32 = (*(block as *const u32).add(6)).to_le();
  let w07: u32 = (*(block as *const u32).add(7)).to_le();
  let w08: u32 = (*(block as *const u32).add(8)).to_le();
  let w09: u32 = (*(block as *const u32).add(9)).to_le();
  let w10: u32 = (*(block as *const u32).add(10)).to_le();
  let w11: u32 = (*(block as *const u32).add(11)).to_le();
  let w12: u32 = (*(block as *const u32).add(12)).to_le();
  let w13: u32 = (*(block as *const u32).add(13)).to_le();
  let w14: u32 = (*(block as *const u32).add(14)).to_le();
  let w15: u32 = (*(block as *const u32).add(15)).to_le();

  // 0 .. 4
  a = ff::<07>(a, b, c, d, w00, 0xd76aa478);
  d = ff::<12>(d, a, b, c, w01, 0xe8c7b756);
  c = ff::<17>(c, d, a, b, w02, 0x242070db);
  b = ff::<22>(b, c, d, a, w03, 0xc1bdceee);

  // 4 .. 8
  a = ff::<07>(a, b, c, d, w04, 0xf57c0faf);
  d = ff::<12>(d, a, b, c, w05, 0x4787c62a);
  c = ff::<17>(c, d, a, b, w06, 0xa8304613);
  b = ff::<22>(b, c, d, a, w07, 0xfd469501);

  // 8 .. 12
  a = ff::<07>(a, b, c, d, w08, 0x698098d8);
  d = ff::<12>(d, a, b, c, w09, 0x8b44f7af);
  c = ff::<17>(c, d, a, b, w10, 0xffff5bb1);
  b = ff::<22>(b, c, d, a, w11, 0x895cd7be);

  // 12 .. 16
  a = ff::<07>(a, b, c, d, w12, 0x6b901122);
  d = ff::<12>(d, a, b, c, w13, 0xfd987193);
  c = ff::<17>(c, d, a, b, w14, 0xa679438e);
  b = ff::<22>(b, c, d, a, w15, 0x49b40821);

  // 16 .. 20
  a = gg::<05>(a, b, c, d, w01, 0xf61e2562);
  d = gg::<09>(d, a, b, c, w06, 0xc040b340);
  c = gg::<14>(c, d, a, b, w11, 0x265e5a51);
  b = gg::<20>(b, c, d, a, w00, 0xe9b6c7aa);

  // 20 .. 24
  a = gg::<05>(a, b, c, d, w05, 0xd62f105d);
  d = gg::<09>(d, a, b, c, w10, 0x02441453);
  c = gg::<14>(c, d, a, b, w15, 0xd8a1e681);
  b = gg::<20>(b, c, d, a, w04, 0xe7d3fbc8);

  // 24 .. 28
  a = gg::<05>(a, b, c, d, w09, 0x21e1cde6);
  d = gg::<09>(d, a, b, c, w14, 0xc33707d6);
  c = gg::<14>(c, d, a, b, w03, 0xf4d50d87);
  b = gg::<20>(b, c, d, a, w08, 0x455a14ed);

  // 28 .. 32
  a = gg::<05>(a, b, c, d, w13, 0xa9e3e905);
  d = gg::<09>(d, a, b, c, w02, 0xfcefa3f8);
  c = gg::<14>(c, d, a, b, w07, 0x676f02d9);
  b = gg::<20>(b, c, d, a, w12, 0x8d2a4c8a);

  // 32 .. 36
  a = hh::<04>(a, b, c, d, w05, 0xfffa3942);
  d = hh::<11>(d, a, b, c, w08, 0x8771f681);
  c = hh::<16>(c, d, a, b, w11, 0x6d9d6122);
  b = hh::<23>(b, c, d, a, w14, 0xfde5380c);

  // 36 .. 40
  a = hh::<04>(a, b, c, d, w01, 0xa4beea44);
  d = hh::<11>(d, a, b, c, w04, 0x4bdecfa9);
  c = hh::<16>(c, d, a, b, w07, 0xf6bb4b60);
  b = hh::<23>(b, c, d, a, w10, 0xbebfbc70);

  // 40 .. 44
  a = hh::<04>(a, b, c, d, w13, 0x289b7ec6);
  d = hh::<11>(d, a, b, c, w00, 0xeaa127fa);
  c = hh::<16>(c, d, a, b, w03, 0xd4ef3085);
  b = hh::<23>(b, c, d, a, w06, 0x04881d05);

  // 44 .. 48
  a = hh::<04>(a, b, c, d, w09, 0xd9d4d039);
  d = hh::<11>(d, a, b, c, w12, 0xe6db99e5);
  c = hh::<16>(c, d, a, b, w15, 0x1fa27cf8);
  b = hh::<23>(b, c, d, a, w02, 0xc4ac5665);

  // 48 .. 52
  a = ii::<06>(a, b, c, d, w00, 0xf4292244);
  d = ii::<10>(d, a, b, c, w07, 0x432aff97);
  c = ii::<15>(c, d, a, b, w14, 0xab9423a7);
  b = ii::<21>(b, c, d, a, w05, 0xfc93a039);

  // 52 .. 56
  a = ii::<06>(a, b, c, d, w12, 0x655b59c3);
  d = ii::<10>(d, a, b, c, w03, 0x8f0ccc92);
  c = ii::<15>(c, d, a, b, w10, 0xffeff47d);
  b = ii::<21>(b, c, d, a, w01, 0x85845dd1);

  // 56 .. 60
  a = ii::<06>(a, b, c, d, w08, 0x6fa87e4f);
  d = ii::<10>(d, a, b, c, w15, 0xfe2ce6e0);
  c = ii::<15>(c, d, a, b, w06, 0xa3014314);
  b = ii::<21>(b, c, d, a, w13, 0x4e0811a1);

  // 60 .. 64
  a = ii::<06>(a, b, c, d, w04, 0xf7537e82);
  d = ii::<10>(d, a, b, c, w11, 0xbd3af235);
  c = ii::<15>(c, d, a, b, w02, 0x2ad7d2bb);
  b = ii::<21>(b, c, d, a, w09, 0xeb86d391);

  *state.add(0) = (*state.add(0)).wrapping_add(a);
  *state.add(1) = (*state.add(1)).wrapping_add(b);
  *state.add(2) = (*state.add(2)).wrapping_add(c);
  *state.add(3) = (*state.add(3)).wrapping_add(d);
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::*;

  #[test]
  fn test()
  {
    let mut state = [0; 4];
    MD5_COMPRESS.iter().for_each(|t| {
      state = t.0;
      unsafe { md5_compress_generic(state.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, state);
    });
  }
}
