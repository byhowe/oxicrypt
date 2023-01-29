macro_rules! r0 {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $block:ident, $w:ident, $i:expr) => {{
    $w[$i] = (*($block as *const u32).add($i)).to_be();
    $e = $e
      .wrapping_add(0x5a827999)
      .wrapping_add($a.rotate_left(5))
      .wrapping_add($d ^ ($b & ($c ^ $d)))
      .wrapping_add($w[$i]);
    $b = $b.rotate_left(30);
  }};
}

macro_rules! r1 {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $block:ident, $w:ident, $i:expr) => {{
    $w[$i & 15] = ($w[($i + 13) & 15] ^ $w[($i + 8) & 15] ^ $w[($i + 2) & 15] ^ $w[$i & 15]).rotate_left(1);
    $e = $e
      .wrapping_add(0x5a827999)
      .wrapping_add($a.rotate_left(5))
      .wrapping_add($d ^ ($b & ($c ^ $d)))
      .wrapping_add($w[$i & 15]);
    $b = $b.rotate_left(30);
  }};
}

macro_rules! r2 {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $block:ident, $w:ident, $i:expr) => {{
    $w[$i & 15] = ($w[($i + 13) & 15] ^ $w[($i + 8) & 15] ^ $w[($i + 2) & 15] ^ $w[$i & 15]).rotate_left(1);
    $e = $e
      .wrapping_add(0x6ed9eba1)
      .wrapping_add($a.rotate_left(5))
      .wrapping_add($b ^ $c ^ $d)
      .wrapping_add($w[$i & 15]);
    $b = $b.rotate_left(30);
  }};
}

macro_rules! r3 {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $block:ident, $w:ident, $i:expr) => {{
    $w[$i & 15] = ($w[($i + 13) & 15] ^ $w[($i + 8) & 15] ^ $w[($i + 2) & 15] ^ $w[$i & 15]).rotate_left(1);
    $e = $e
      .wrapping_add(0x8f1bbcdc)
      .wrapping_add($a.rotate_left(5))
      .wrapping_add(($b & $c) | ($d & ($b | $c)))
      .wrapping_add($w[$i & 15]);
    $b = $b.rotate_left(30);
  }};
}

macro_rules! r4 {
  ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $block:ident, $w:ident, $i:expr) => {{
    $w[$i & 15] = ($w[($i + 13) & 15] ^ $w[($i + 8) & 15] ^ $w[($i + 2) & 15] ^ $w[$i & 15]).rotate_left(1);
    $e = $e
      .wrapping_add(0xca62c1d6)
      .wrapping_add($a.rotate_left(5))
      .wrapping_add($b ^ $c ^ $d)
      .wrapping_add($w[$i & 15]);
    $b = $b.rotate_left(30);
  }};
}

/// Compression function used by the SHA-1 algorithm. You shouldn't use this function unless you
/// want to implement the algorithm by yourself.
///
/// It is implemented in pure Rust.
///
/// # Safety
///
/// The caller must guarantee that the passed variables point to valid memory spaces. `state` must
/// point to an array with a length of 5 (20 bytes). `block` must point to an array with a length
/// of 64 (64 bytes).
#[allow(clippy::many_single_char_names)]
#[allow(unused_assignments)]
pub const unsafe fn sha1_compress_generic(state: *mut u32, block: *const u8)
{
  let mut a: u32 = *state.add(0);
  let mut b: u32 = *state.add(1);
  let mut c: u32 = *state.add(2);
  let mut d: u32 = *state.add(3);
  let mut e: u32 = *state.add(4);

  let mut w: [u32; 16] = [0; 16];

  r0!(a, b, c, d, e, block, w, 0);
  r0!(e, a, b, c, d, block, w, 1);
  r0!(d, e, a, b, c, block, w, 2);
  r0!(c, d, e, a, b, block, w, 3);
  r0!(b, c, d, e, a, block, w, 4);
  r0!(a, b, c, d, e, block, w, 5);
  r0!(e, a, b, c, d, block, w, 6);
  r0!(d, e, a, b, c, block, w, 7);
  r0!(c, d, e, a, b, block, w, 8);
  r0!(b, c, d, e, a, block, w, 9);
  r0!(a, b, c, d, e, block, w, 10);
  r0!(e, a, b, c, d, block, w, 11);
  r0!(d, e, a, b, c, block, w, 12);
  r0!(c, d, e, a, b, block, w, 13);
  r0!(b, c, d, e, a, block, w, 14);
  r0!(a, b, c, d, e, block, w, 15);
  r1!(e, a, b, c, d, block, w, 16);
  r1!(d, e, a, b, c, block, w, 17);
  r1!(c, d, e, a, b, block, w, 18);
  r1!(b, c, d, e, a, block, w, 19);

  r2!(a, b, c, d, e, block, w, 20);
  r2!(e, a, b, c, d, block, w, 21);
  r2!(d, e, a, b, c, block, w, 22);
  r2!(c, d, e, a, b, block, w, 23);
  r2!(b, c, d, e, a, block, w, 24);
  r2!(a, b, c, d, e, block, w, 25);
  r2!(e, a, b, c, d, block, w, 26);
  r2!(d, e, a, b, c, block, w, 27);
  r2!(c, d, e, a, b, block, w, 28);
  r2!(b, c, d, e, a, block, w, 29);
  r2!(a, b, c, d, e, block, w, 30);
  r2!(e, a, b, c, d, block, w, 31);
  r2!(d, e, a, b, c, block, w, 32);
  r2!(c, d, e, a, b, block, w, 33);
  r2!(b, c, d, e, a, block, w, 34);
  r2!(a, b, c, d, e, block, w, 35);
  r2!(e, a, b, c, d, block, w, 36);
  r2!(d, e, a, b, c, block, w, 37);
  r2!(c, d, e, a, b, block, w, 38);
  r2!(b, c, d, e, a, block, w, 39);

  r3!(a, b, c, d, e, block, w, 40);
  r3!(e, a, b, c, d, block, w, 41);
  r3!(d, e, a, b, c, block, w, 42);
  r3!(c, d, e, a, b, block, w, 43);
  r3!(b, c, d, e, a, block, w, 44);
  r3!(a, b, c, d, e, block, w, 45);
  r3!(e, a, b, c, d, block, w, 46);
  r3!(d, e, a, b, c, block, w, 47);
  r3!(c, d, e, a, b, block, w, 48);
  r3!(b, c, d, e, a, block, w, 49);
  r3!(a, b, c, d, e, block, w, 50);
  r3!(e, a, b, c, d, block, w, 51);
  r3!(d, e, a, b, c, block, w, 52);
  r3!(c, d, e, a, b, block, w, 53);
  r3!(b, c, d, e, a, block, w, 54);
  r3!(a, b, c, d, e, block, w, 55);
  r3!(e, a, b, c, d, block, w, 56);
  r3!(d, e, a, b, c, block, w, 57);
  r3!(c, d, e, a, b, block, w, 58);
  r3!(b, c, d, e, a, block, w, 59);

  r4!(a, b, c, d, e, block, w, 60);
  r4!(e, a, b, c, d, block, w, 61);
  r4!(d, e, a, b, c, block, w, 62);
  r4!(c, d, e, a, b, block, w, 63);
  r4!(b, c, d, e, a, block, w, 64);
  r4!(a, b, c, d, e, block, w, 65);
  r4!(e, a, b, c, d, block, w, 66);
  r4!(d, e, a, b, c, block, w, 67);
  r4!(c, d, e, a, b, block, w, 68);
  r4!(b, c, d, e, a, block, w, 69);
  r4!(a, b, c, d, e, block, w, 70);
  r4!(e, a, b, c, d, block, w, 71);
  r4!(d, e, a, b, c, block, w, 72);
  r4!(c, d, e, a, b, block, w, 73);
  r4!(b, c, d, e, a, block, w, 74);
  r4!(a, b, c, d, e, block, w, 75);
  r4!(e, a, b, c, d, block, w, 76);
  r4!(d, e, a, b, c, block, w, 77);
  r4!(c, d, e, a, b, block, w, 78);
  r4!(b, c, d, e, a, block, w, 79);

  *state.add(0) = (*state.add(0)).wrapping_add(a);
  *state.add(1) = (*state.add(1)).wrapping_add(b);
  *state.add(2) = (*state.add(2)).wrapping_add(c);
  *state.add(3) = (*state.add(3)).wrapping_add(d);
  *state.add(4) = (*state.add(4)).wrapping_add(e);
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::*;

  #[test]
  fn test()
  {
    let mut state = [0; 5];
    SHA1_COMPRESS.iter().for_each(|t| {
      state = t.0;
      unsafe { sha1_compress_generic(state.as_mut_ptr(), t.2.as_ptr()) };
      assert_eq!(t.1, state);
    });
  }
}
