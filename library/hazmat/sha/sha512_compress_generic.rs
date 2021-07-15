macro_rules! sha2_64_f {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $m1:ident, $m2:ident, $m3:ident, $m4:ident, $magic:expr) => {{
    let a_rho: u64 = $a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39);
    let e_rho: u64 = $e.rotate_right(14) ^ $e.rotate_right(18) ^ $e.rotate_right(41);
    let m2_sigma: u64 = $m2.rotate_right(19) ^ $m2.rotate_right(61) ^ ($m2 >> 6);
    let m4_sigma: u64 = $m4.rotate_right(1) ^ $m4.rotate_right(8) ^ ($m4 >> 7);
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

/// Compression function used by the SHA-2 family of functions, namely SHA-384, SHA-512,
/// SHA-512/224 and SHA-512/256. You shouldn't use this function unless you want to implement the
/// algorithms by yourself.
///
/// It is implemented in pure Rust.
///
/// # Safety
///
/// The caller must guarantee that the passed variables point to valid memory spaces. `state` must
/// point to an array with a length of 8 (64 bytes). `block` must point to an array with a length
/// of 128 (128 bytes).
#[allow(clippy::many_single_char_names)]
#[allow(unused_assignments)]
pub unsafe fn sha512_compress_generic(state: *mut u64, block: *const u8)
{
  let mut a: u64 = *state.add(0);
  let mut b: u64 = *state.add(1);
  let mut c: u64 = *state.add(2);
  let mut d: u64 = *state.add(3);
  let mut e: u64 = *state.add(4);
  let mut f: u64 = *state.add(5);
  let mut g: u64 = *state.add(6);
  let mut h: u64 = *state.add(7);

  let mut w00: u64 = (*(block as *const u64).add(0)).to_be();
  let mut w01: u64 = (*(block as *const u64).add(1)).to_be();
  let mut w02: u64 = (*(block as *const u64).add(2)).to_be();
  let mut w03: u64 = (*(block as *const u64).add(3)).to_be();
  let mut w04: u64 = (*(block as *const u64).add(4)).to_be();
  let mut w05: u64 = (*(block as *const u64).add(5)).to_be();
  let mut w06: u64 = (*(block as *const u64).add(6)).to_be();
  let mut w07: u64 = (*(block as *const u64).add(7)).to_be();
  let mut w08: u64 = (*(block as *const u64).add(8)).to_be();
  let mut w09: u64 = (*(block as *const u64).add(9)).to_be();
  let mut w10: u64 = (*(block as *const u64).add(10)).to_be();
  let mut w11: u64 = (*(block as *const u64).add(11)).to_be();
  let mut w12: u64 = (*(block as *const u64).add(12)).to_be();
  let mut w13: u64 = (*(block as *const u64).add(13)).to_be();
  let mut w14: u64 = (*(block as *const u64).add(14)).to_be();
  let mut w15: u64 = (*(block as *const u64).add(15)).to_be();

  sha2_64_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0x428a2f98d728ae22);
  sha2_64_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0x7137449123ef65cd);
  sha2_64_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0xb5c0fbcfec4d3b2f);
  sha2_64_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0xe9b5dba58189dbbc);
  sha2_64_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x3956c25bf348b538);
  sha2_64_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x59f111f1b605d019);
  sha2_64_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x923f82a4af194f9b);
  sha2_64_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0xab1c5ed5da6d8118);
  sha2_64_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0xd807aa98a3030242);
  sha2_64_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0x12835b0145706fbe);
  sha2_64_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0x243185be4ee4b28c);
  sha2_64_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0x550c7dc3d5ffb4e2);
  sha2_64_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0x72be5d74f27b896f);
  sha2_64_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0x80deb1fe3b1696b1);
  sha2_64_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0x9bdc06a725c71235);
  sha2_64_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0xc19bf174cf692694);

  sha2_64_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0xe49b69c19ef14ad2);
  sha2_64_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0xefbe4786384f25e3);
  sha2_64_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0x0fc19dc68b8cd5b5);
  sha2_64_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0x240ca1cc77ac9c65);
  sha2_64_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x2de92c6f592b0275);
  sha2_64_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x4a7484aa6ea6e483);
  sha2_64_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x5cb0a9dcbd41fbd4);
  sha2_64_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x76f988da831153b5);
  sha2_64_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0x983e5152ee66dfab);
  sha2_64_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0xa831c66d2db43210);
  sha2_64_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0xb00327c898fb213f);
  sha2_64_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0xbf597fc7beef0ee4);
  sha2_64_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0xc6e00bf33da88fc2);
  sha2_64_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0xd5a79147930aa725);
  sha2_64_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0x06ca6351e003826f);
  sha2_64_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0x142929670a0e6e70);

  sha2_64_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0x27b70a8546d22ffc);
  sha2_64_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0x2e1b21385c26c926);
  sha2_64_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0x4d2c6dfc5ac42aed);
  sha2_64_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0x53380d139d95b3df);
  sha2_64_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x650a73548baf63de);
  sha2_64_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x766a0abb3c77b2a8);
  sha2_64_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x81c2c92e47edaee6);
  sha2_64_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x92722c851482353b);
  sha2_64_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0xa2bfe8a14cf10364);
  sha2_64_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0xa81a664bbc423001);
  sha2_64_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0xc24b8b70d0f89791);
  sha2_64_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0xc76c51a30654be30);
  sha2_64_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0xd192e819d6ef5218);
  sha2_64_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0xd69906245565a910);
  sha2_64_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0xf40e35855771202a);
  sha2_64_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0x106aa07032bbd1b8);

  sha2_64_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0x19a4c116b8d2d0c8);
  sha2_64_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0x1e376c085141ab53);
  sha2_64_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0x2748774cdf8eeb99);
  sha2_64_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0x34b0bcb5e19b48a8);
  sha2_64_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x391c0cb3c5c95a63);
  sha2_64_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x4ed8aa4ae3418acb);
  sha2_64_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x5b9cca4f7763e373);
  sha2_64_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x682e6ff3d6b2b8a3);
  sha2_64_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0x748f82ee5defb2fc);
  sha2_64_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0x78a5636f43172f60);
  sha2_64_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0x84c87814a1f0ab72);
  sha2_64_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0x8cc702081a6439ec);
  sha2_64_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0x90befffa23631e28);
  sha2_64_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0xa4506cebde82bde9);
  sha2_64_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0xbef9a3f7b2c67915);
  sha2_64_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0xc67178f2e372532b);

  sha2_64_f!(a, b, c, d, e, f, g, h, w00, w14, w09, w01, 0xca273eceea26619c);
  sha2_64_f!(h, a, b, c, d, e, f, g, w01, w15, w10, w02, 0xd186b8c721c0c207);
  sha2_64_f!(g, h, a, b, c, d, e, f, w02, w00, w11, w03, 0xeada7dd6cde0eb1e);
  sha2_64_f!(f, g, h, a, b, c, d, e, w03, w01, w12, w04, 0xf57d4f7fee6ed178);
  sha2_64_f!(e, f, g, h, a, b, c, d, w04, w02, w13, w05, 0x06f067aa72176fba);
  sha2_64_f!(d, e, f, g, h, a, b, c, w05, w03, w14, w06, 0x0a637dc5a2c898a6);
  sha2_64_f!(c, d, e, f, g, h, a, b, w06, w04, w15, w07, 0x113f9804bef90dae);
  sha2_64_f!(b, c, d, e, f, g, h, a, w07, w05, w00, w08, 0x1b710b35131c471b);
  sha2_64_f!(a, b, c, d, e, f, g, h, w08, w06, w01, w09, 0x28db77f523047d84);
  sha2_64_f!(h, a, b, c, d, e, f, g, w09, w07, w02, w10, 0x32caab7b40c72493);
  sha2_64_f!(g, h, a, b, c, d, e, f, w10, w08, w03, w11, 0x3c9ebe0a15c9bebc);
  sha2_64_f!(f, g, h, a, b, c, d, e, w11, w09, w04, w12, 0x431d67c49c100d4c);
  sha2_64_f!(e, f, g, h, a, b, c, d, w12, w10, w05, w13, 0x4cc5d4becb3e42b6);
  sha2_64_f!(d, e, f, g, h, a, b, c, w13, w11, w06, w14, 0x597f299cfc657e2a);
  sha2_64_f!(c, d, e, f, g, h, a, b, w14, w12, w07, w15, 0x5fcb6fab3ad6faec);
  sha2_64_f!(b, c, d, e, f, g, h, a, w15, w13, w08, w00, 0x6c44198c4a475817);

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
  fn test()
  {
    let mut state = [0; 8];
    SHA512_COMPRESS.iter().for_each(|t| {
      state = t.0;
      unsafe { sha512_compress_generic(state.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, state);
    });
  }
}
