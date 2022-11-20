#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", doc)))]
compile_error!("`aes_x86_aesni_aes_encrypt` module is only available for `x86` and `x86_64`");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn encrypt1<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));

  b0 = _mm_xor_si128(b0, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
}

#[inline(always)]
unsafe fn encrypt2<const N: usize>(block: *mut u8, key_schedule: *const u8)
{
  assert!(N == 10 || N == 12 || N == 14);

  let mut k0: __m128i = _mm_loadu_si128((key_schedule as *const __m128i).add(0));
  let mut b0: __m128i = _mm_loadu_si128((block as *const __m128i).add(0));
  let mut b1: __m128i = _mm_loadu_si128((block as *const __m128i).add(1));

  b0 = _mm_xor_si128(b0, k0);
  b1 = _mm_xor_si128(b1, k0);

  for i in 1 .. N {
    k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(i));
    b0 = _mm_aesenc_si128(b0, k0);
    b1 = _mm_aesenc_si128(b1, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);
  b1 = _mm_aesenclast_si128(b1, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
}

#[inline(always)]
unsafe fn encrypt4<const N: usize>(block: *mut u8, key_schedule: *const u8)
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
    b0 = _mm_aesenc_si128(b0, k0);
    b1 = _mm_aesenc_si128(b1, k0);
    b2 = _mm_aesenc_si128(b2, k0);
    b3 = _mm_aesenc_si128(b3, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);
  b1 = _mm_aesenclast_si128(b1, k0);
  b2 = _mm_aesenclast_si128(b2, k0);
  b3 = _mm_aesenclast_si128(b3, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
}

#[inline(always)]
unsafe fn encrypt8<const N: usize>(block: *mut u8, key_schedule: *const u8)
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
    b0 = _mm_aesenc_si128(b0, k0);
    b1 = _mm_aesenc_si128(b1, k0);
    b2 = _mm_aesenc_si128(b2, k0);
    b3 = _mm_aesenc_si128(b3, k0);
    b4 = _mm_aesenc_si128(b4, k0);
    b5 = _mm_aesenc_si128(b5, k0);
    b6 = _mm_aesenc_si128(b6, k0);
    b7 = _mm_aesenc_si128(b7, k0);
  }

  k0 = _mm_loadu_si128((key_schedule as *const __m128i).add(N));
  b0 = _mm_aesenclast_si128(b0, k0);
  b1 = _mm_aesenclast_si128(b1, k0);
  b2 = _mm_aesenclast_si128(b2, k0);
  b3 = _mm_aesenclast_si128(b3, k0);
  b4 = _mm_aesenclast_si128(b4, k0);
  b5 = _mm_aesenclast_si128(b5, k0);
  b6 = _mm_aesenclast_si128(b6, k0);
  b7 = _mm_aesenclast_si128(b7, k0);

  _mm_storeu_si128((block as *mut __m128i).add(0), b0);
  _mm_storeu_si128((block as *mut __m128i).add(1), b1);
  _mm_storeu_si128((block as *mut __m128i).add(2), b2);
  _mm_storeu_si128((block as *mut __m128i).add(3), b3);
  _mm_storeu_si128((block as *mut __m128i).add(4), b4);
  _mm_storeu_si128((block as *mut __m128i).add(5), b5);
  _mm_storeu_si128((block as *mut __m128i).add(6), b6);
  _mm_storeu_si128((block as *mut __m128i).add(7), b7);
}

// AES128 ENCRYPT

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  encrypt1::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  encrypt2::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  encrypt4::<10>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  encrypt8::<10>(block, key_schedule);
}

// AES192 ENCRYPT

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  encrypt1::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  encrypt2::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  encrypt4::<12>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  encrypt8::<12>(block, key_schedule);
}

// AES256 ENCRYPT

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_encrypt1(block: *mut u8, key_schedule: *const u8)
{
  encrypt1::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_encrypt2(block: *mut u8, key_schedule: *const u8)
{
  encrypt2::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_encrypt4(block: *mut u8, key_schedule: *const u8)
{
  encrypt4::<14>(block, key_schedule);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_encrypt8(block: *mut u8, key_schedule: *const u8)
{
  encrypt8::<14>(block, key_schedule);
}

#[cfg(test)]
mod tests
{
  use oxicrypt_test_vectors::Aes;
  use oxicrypt_test_vectors::AesVectorsIterator;

  use super::*;

  #[test]
  fn aes128()
  {
    for vectors in AesVectorsIterator::<{ Aes::Aes128 }>::new() {
      let mut block1 = vectors.plaintext_chunks()[0 .. 1].to_vec();
      let mut block2 = vectors.plaintext_chunks()[0 .. 2].to_vec();
      let mut block4 = vectors.plaintext_chunks()[0 .. 4].to_vec();
      let mut block8 = vectors.plaintext_chunks()[0 .. 8].to_vec();

      unsafe {
        aes_x86_aesni_aes128_encrypt1(block1.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes128_encrypt2(block2.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes128_encrypt4(block4.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes128_encrypt8(block8.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
      }

      assert_eq!(block1, vectors.ciphertext_chunks()[0 .. 1]);
      assert_eq!(block2, vectors.ciphertext_chunks()[0 .. 2]);
      assert_eq!(block4, vectors.ciphertext_chunks()[0 .. 4]);
      assert_eq!(block8, vectors.ciphertext_chunks()[0 .. 8]);
    }
  }

  #[test]
  fn aes192()
  {
    for vectors in AesVectorsIterator::<{ Aes::Aes192 }>::new() {
      let mut block1 = vectors.plaintext_chunks()[0 .. 1].to_vec();
      let mut block2 = vectors.plaintext_chunks()[0 .. 2].to_vec();
      let mut block4 = vectors.plaintext_chunks()[0 .. 4].to_vec();
      let mut block8 = vectors.plaintext_chunks()[0 .. 8].to_vec();

      unsafe {
        aes_x86_aesni_aes192_encrypt1(block1.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes192_encrypt2(block2.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes192_encrypt4(block4.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes192_encrypt8(block8.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
      }

      assert_eq!(block1, vectors.ciphertext_chunks()[0 .. 1]);
      assert_eq!(block2, vectors.ciphertext_chunks()[0 .. 2]);
      assert_eq!(block4, vectors.ciphertext_chunks()[0 .. 4]);
      assert_eq!(block8, vectors.ciphertext_chunks()[0 .. 8]);
    }
  }

  #[test]
  fn aes256()
  {
    for vectors in AesVectorsIterator::<{ Aes::Aes256 }>::new() {
      let mut block1 = vectors.plaintext_chunks()[0 .. 1].to_vec();
      let mut block2 = vectors.plaintext_chunks()[0 .. 2].to_vec();
      let mut block4 = vectors.plaintext_chunks()[0 .. 4].to_vec();
      let mut block8 = vectors.plaintext_chunks()[0 .. 8].to_vec();

      unsafe {
        aes_x86_aesni_aes256_encrypt1(block1.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes256_encrypt2(block2.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes256_encrypt4(block4.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
        aes_x86_aesni_aes256_encrypt8(block8.as_mut_ptr() as _, vectors.expanded_key.as_ptr());
      }

      assert_eq!(block1, vectors.ciphertext_chunks()[0 .. 1]);
      assert_eq!(block2, vectors.ciphertext_chunks()[0 .. 2]);
      assert_eq!(block4, vectors.ciphertext_chunks()[0 .. 4]);
      assert_eq!(block8, vectors.ciphertext_chunks()[0 .. 8]);
    }
  }
}
