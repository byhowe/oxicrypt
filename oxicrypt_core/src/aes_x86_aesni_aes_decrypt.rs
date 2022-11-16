#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", doc)))]
compile_error!("`aes_x86_aesni_aes_decrypt` module is only available for `x86` and `x86_64`");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn aes_decrypt1<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));

  b0 = _mm_xor_si128(b0, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
}

#[inline(always)]
unsafe fn aes_decrypt2<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
    b1 = _mm_aesdec_si128(b1, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);
  b1 = _mm_aesdeclast_si128(b1, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
}

#[inline(always)]
unsafe fn aes_decrypt4<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));
  let mut b2: __m128i = _mm_loadu_si128((block as *const __m128i).add(2));
  let mut b3: __m128i = _mm_loadu_si128((block as *const __m128i).add(3));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);
  b2 = _mm_xor_si128(b2, k0);
  b3 = _mm_xor_si128(b3, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
    b1 = _mm_aesdec_si128(b1, k0);
    b2 = _mm_aesdec_si128(b2, k0);
    b3 = _mm_aesdec_si128(b3, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);
  b1 = _mm_aesdeclast_si128(b1, k0);
  b2 = _mm_aesdeclast_si128(b2, k0);
  b3 = _mm_aesdeclast_si128(b3, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
}

#[inline(always)]
unsafe fn aes_decrypt8<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));
  let mut b2: __m128i = _mm_loadu_si128((block as *const __m128i).add(2));
  let mut b3: __m128i = _mm_loadu_si128((block as *const __m128i).add(3));
  let mut b4: __m128i = _mm_loadu_si128((block as *const __m128i).add(4));
  let mut b5: __m128i = _mm_loadu_si128((block as *const __m128i).add(5));
  let mut b6: __m128i = _mm_loadu_si128((block as *const __m128i).add(6));
  let mut b7: __m128i = _mm_loadu_si128((block as *const __m128i).add(7));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);
  b2 = _mm_xor_si128(b2, k0);
  b3 = _mm_xor_si128(b3, k0);
  b4 = _mm_xor_si128(b4, k0);
  b5 = _mm_xor_si128(b5, k0);
  b6 = _mm_xor_si128(b6, k0);
  b7 = _mm_xor_si128(b7, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesdec_si128(b0, k0);
    b1 = _mm_aesdec_si128(b1, k0);
    b2 = _mm_aesdec_si128(b2, k0);
    b3 = _mm_aesdec_si128(b3, k0);
    b4 = _mm_aesdec_si128(b4, k0);
    b5 = _mm_aesdec_si128(b5, k0);
    b6 = _mm_aesdec_si128(b6, k0);
    b7 = _mm_aesdec_si128(b7, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesdeclast_si128(b0, k0);
  b1 = _mm_aesdeclast_si128(b1, k0);
  b2 = _mm_aesdeclast_si128(b2, k0);
  b3 = _mm_aesdeclast_si128(b3, k0);
  b4 = _mm_aesdeclast_si128(b4, k0);
  b5 = _mm_aesdeclast_si128(b5, k0);
  b6 = _mm_aesdeclast_si128(b6, k0);
  b7 = _mm_aesdeclast_si128(b7, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
  _mm_storeu_si128((block as *mut __m128i).add(4), b4);
  _mm_storeu_si128((block as *mut __m128i).add(5), b5);
  _mm_storeu_si128((block as *mut __m128i).add(6), b6);
  _mm_storeu_si128((block as *mut __m128i).add(7), b7);
}

// AES128 DECRYPT

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt1::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt2::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt4::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt8::<10>(block, key_schedule);
}

// AES192 DECRYPT

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt1::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt2::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt4::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt8::<12>(block, key_schedule);
}

// AES256 DECRYPT

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_decrypt1(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt1::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_decrypt2(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt2::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_decrypt4(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt4::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_decrypt8(block: *mut u8, key_schedule: *const u8)
{
  aes_decrypt8::<14>(block, key_schedule);
}

#[cfg(test)]
mod tests
{
  use super::*;
  use crate::test_vectors::AES128;
  use crate::test_vectors::AES192;
  use crate::test_vectors::AES256;

  #[test]
  fn aes128()
  {
    for vectors in AES128 {
      let mut block1 = [vectors.ciphertext[0]];
      let mut block2 = [vectors.ciphertext[0], vectors.ciphertext[1]];
      let mut block4 = [
        vectors.ciphertext[0],
        vectors.ciphertext[1],
        vectors.ciphertext[2],
        vectors.ciphertext[3],
      ];
      let mut block8 = [
        vectors.ciphertext[0],
        vectors.ciphertext[1],
        vectors.ciphertext[2],
        vectors.ciphertext[3],
        vectors.ciphertext[4],
        vectors.ciphertext[5],
        vectors.ciphertext[6],
        vectors.ciphertext[7],
      ];

      unsafe {
        aes_x86_aesni_aes128_decrypt1(block1.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes128_decrypt2(block2.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes128_decrypt4(block4.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes128_decrypt8(block8.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
      }

      assert_eq!(block1, [vectors.plaintext[0]]);
      assert_eq!(block2, [vectors.plaintext[0], vectors.plaintext[1],]);
      assert_eq!(
        block4,
        [
          vectors.plaintext[0],
          vectors.plaintext[1],
          vectors.plaintext[2],
          vectors.plaintext[3],
        ]
      );
      assert_eq!(
        block8,
        [
          vectors.plaintext[0],
          vectors.plaintext[1],
          vectors.plaintext[2],
          vectors.plaintext[3],
          vectors.plaintext[4],
          vectors.plaintext[5],
          vectors.plaintext[6],
          vectors.plaintext[7],
        ]
      );
    }
  }

  #[test]
  fn aes192()
  {
    for vectors in AES192 {
      let mut block1 = [vectors.ciphertext[0]];
      let mut block2 = [vectors.ciphertext[0], vectors.ciphertext[1]];
      let mut block4 = [
        vectors.ciphertext[0],
        vectors.ciphertext[1],
        vectors.ciphertext[2],
        vectors.ciphertext[3],
      ];
      let mut block8 = [
        vectors.ciphertext[0],
        vectors.ciphertext[1],
        vectors.ciphertext[2],
        vectors.ciphertext[3],
        vectors.ciphertext[4],
        vectors.ciphertext[5],
        vectors.ciphertext[6],
        vectors.ciphertext[7],
      ];

      unsafe {
        aes_x86_aesni_aes192_decrypt1(block1.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes192_decrypt2(block2.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes192_decrypt4(block4.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes192_decrypt8(block8.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
      }

      assert_eq!(block1, [vectors.plaintext[0]]);
      assert_eq!(block2, [vectors.plaintext[0], vectors.plaintext[1],]);
      assert_eq!(
        block4,
        [
          vectors.plaintext[0],
          vectors.plaintext[1],
          vectors.plaintext[2],
          vectors.plaintext[3],
        ]
      );
      assert_eq!(
        block8,
        [
          vectors.plaintext[0],
          vectors.plaintext[1],
          vectors.plaintext[2],
          vectors.plaintext[3],
          vectors.plaintext[4],
          vectors.plaintext[5],
          vectors.plaintext[6],
          vectors.plaintext[7],
        ]
      );
    }
  }

  #[test]
  fn aes256()
  {
    for vectors in AES256 {
      let mut block1 = [vectors.ciphertext[0]];
      let mut block2 = [vectors.ciphertext[0], vectors.ciphertext[1]];
      let mut block4 = [
        vectors.ciphertext[0],
        vectors.ciphertext[1],
        vectors.ciphertext[2],
        vectors.ciphertext[3],
      ];
      let mut block8 = [
        vectors.ciphertext[0],
        vectors.ciphertext[1],
        vectors.ciphertext[2],
        vectors.ciphertext[3],
        vectors.ciphertext[4],
        vectors.ciphertext[5],
        vectors.ciphertext[6],
        vectors.ciphertext[7],
      ];

      unsafe {
        aes_x86_aesni_aes256_decrypt1(block1.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes256_decrypt2(block2.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes256_decrypt4(block4.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
        aes_x86_aesni_aes256_decrypt8(block8.as_mut_ptr() as _, vectors.inversed_key.as_ptr());
      }

      assert_eq!(block1, [vectors.plaintext[0]]);
      assert_eq!(block2, [vectors.plaintext[0], vectors.plaintext[1],]);
      assert_eq!(
        block4,
        [
          vectors.plaintext[0],
          vectors.plaintext[1],
          vectors.plaintext[2],
          vectors.plaintext[3],
        ]
      );
      assert_eq!(
        block8,
        [
          vectors.plaintext[0],
          vectors.plaintext[1],
          vectors.plaintext[2],
          vectors.plaintext[3],
          vectors.plaintext[4],
          vectors.plaintext[5],
          vectors.plaintext[6],
          vectors.plaintext[7],
        ]
      );
    }
  }
}
