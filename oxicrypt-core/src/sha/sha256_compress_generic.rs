macro_rules! sha2_32_f {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $m1:ident, $m2:ident, $m3:ident, $m4:ident, $magic:expr) => {{
    let a_rho: u32 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
    let e_rho: u32 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
    let m2_sigma: u32 = $m2.rotate_right(17) ^ $m2.rotate_right(19) ^ ($m2 >> 10);
    let m4_sigma: u32 = $m4.rotate_right(7) ^ $m4.rotate_right(18) ^ ($m4 >> 3);
    $h = $h
      .wrapping_add($magic)
      .wrapping_add(e_rho)
      .wrapping_add(($e & $f) ^ (!$e & $g))
      .wrapping_add($m1);
    $d = $d.wrapping_add($h);
    $h = $h.wrapping_add(a_rho).wrapping_add(($a & $b) | (($a | $b) & $c));
    $m1 = $m1.wrapping_add(m2_sigma).wrapping_add($m3).wrapping_add(m4_sigma);
  }};
}

/// Compression function used by the SHA-2 family of functions, namely SHA-224 and SHA-256. You
/// shouldn't use this function unless you want to implement the algorithms by yourself.
///
/// It is implemented in pure Rust.
///
/// # Safety
///
/// The caller must guarantee that the passed variables point to valid memory spaces. `state` must
/// point to an array with a length of 8 (32 bytes). `block` must point to an array with a length
/// of 64 (64 bytes).
#[allow(clippy::many_single_char_names)]
#[allow(unused_assignments)]
pub unsafe fn sha256_compress_generic(state: *mut u32, block: *const u8)
{
  let mut a: u32 = *state.add(0);
  let mut b: u32 = *state.add(1);
  let mut c: u32 = *state.add(2);
  let mut d: u32 = *state.add(3);
  let mut e: u32 = *state.add(4);
  let mut f: u32 = *state.add(5);
  let mut g: u32 = *state.add(6);
  let mut h: u32 = *state.add(7);

  let mut w00: u32 = (*(block as *const u32).add(0)).to_be();
  let mut w01: u32 = (*(block as *const u32).add(1)).to_be();
  let mut w02: u32 = (*(block as *const u32).add(2)).to_be();
  let mut w03: u32 = (*(block as *const u32).add(3)).to_be();
  let mut w04: u32 = (*(block as *const u32).add(4)).to_be();
  let mut w05: u32 = (*(block as *const u32).add(5)).to_be();
  let mut w06: u32 = (*(block as *const u32).add(6)).to_be();
  let mut w07: u32 = (*(block as *const u32).add(7)).to_be();
  let mut w08: u32 = (*(block as *const u32).add(8)).to_be();
  let mut w09: u32 = (*(block as *const u32).add(9)).to_be();
  let mut w10: u32 = (*(block as *const u32).add(10)).to_be();
  let mut w11: u32 = (*(block as *const u32).add(11)).to_be();
  let mut w12: u32 = (*(block as *const u32).add(12)).to_be();
  let mut w13: u32 = (*(block as *const u32).add(13)).to_be();
  let mut w14: u32 = (*(block as *const u32).add(14)).to_be();
  let mut w15: u32 = (*(block as *const u32).add(15)).to_be();

  sha2_32_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0x428a2f98);
  sha2_32_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0x71374491);
  sha2_32_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0xb5c0fbcf);
  sha2_32_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0xe9b5dba5);
  sha2_32_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x3956c25b);
  sha2_32_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x59f111f1);
  sha2_32_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x923f82a4);
  sha2_32_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0xab1c5ed5);
  sha2_32_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0xd807aa98);
  sha2_32_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0x12835b01);
  sha2_32_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0x243185be);
  sha2_32_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0x550c7dc3);
  sha2_32_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0x72be5d74);
  sha2_32_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0x80deb1fe);
  sha2_32_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0x9bdc06a7);
  sha2_32_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0xc19bf174);

  sha2_32_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0xe49b69c1);
  sha2_32_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0xefbe4786);
  sha2_32_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0x0fc19dc6);
  sha2_32_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0x240ca1cc);
  sha2_32_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x2de92c6f);
  sha2_32_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x4a7484aa);
  sha2_32_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x5cb0a9dc);
  sha2_32_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x76f988da);
  sha2_32_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0x983e5152);
  sha2_32_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0xa831c66d);
  sha2_32_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0xb00327c8);
  sha2_32_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0xbf597fc7);
  sha2_32_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0xc6e00bf3);
  sha2_32_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0xd5a79147);
  sha2_32_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0x06ca6351);
  sha2_32_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0x14292967);

  sha2_32_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0x27b70a85);
  sha2_32_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0x2e1b2138);
  sha2_32_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0x4d2c6dfc);
  sha2_32_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0x53380d13);
  sha2_32_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x650a7354);
  sha2_32_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x766a0abb);
  sha2_32_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x81c2c92e);
  sha2_32_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x92722c85);
  sha2_32_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0xa2bfe8a1);
  sha2_32_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0xa81a664b);
  sha2_32_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0xc24b8b70);
  sha2_32_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0xc76c51a3);
  sha2_32_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0xd192e819);
  sha2_32_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0xd6990624);
  sha2_32_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0xf40e3585);
  sha2_32_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0x106aa070);

  sha2_32_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0x19a4c116);
  sha2_32_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0x1e376c08);
  sha2_32_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0x2748774c);
  sha2_32_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0x34b0bcb5);
  sha2_32_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x391c0cb3);
  sha2_32_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x4ed8aa4a);
  sha2_32_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x5b9cca4f);
  sha2_32_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x682e6ff3);
  sha2_32_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0x748f82ee);
  sha2_32_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0x78a5636f);
  sha2_32_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0x84c87814);
  sha2_32_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0x8cc70208);
  sha2_32_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0x90befffa);
  sha2_32_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0xa4506ceb);
  sha2_32_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0xbef9a3f7);
  sha2_32_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0xc67178f2);

  state.add(0).write((*state.add(0)).wrapping_add(a));
  state.add(1).write((*state.add(1)).wrapping_add(b));
  state.add(2).write((*state.add(2)).wrapping_add(c));
  state.add(3).write((*state.add(3)).wrapping_add(d));
  state.add(4).write((*state.add(4)).wrapping_add(e));
  state.add(5).write((*state.add(5)).wrapping_add(f));
  state.add(6).write((*state.add(6)).wrapping_add(g));
  state.add(7).write((*state.add(7)).wrapping_add(h));
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::*;

  #[test]
  fn test_sha256_compress()
  {
    let mut state = [0; 8];
    SHA256_COMPRESS.iter().for_each(|t| {
      state = t.0;
      unsafe { sha256_compress_generic(state.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, state);
    });
  }
}
