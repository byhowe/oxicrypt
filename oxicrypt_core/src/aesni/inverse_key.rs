#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn inverse_key<const ROUNDS: usize>(key_schedule: *mut u8)
{
    let mut k0: __m128i = _mm_loadu_si128(key_schedule.cast::<__m128i>().add(0));
    let mut k1: __m128i = _mm_loadu_si128(key_schedule.cast::<__m128i>().add(ROUNDS));
    _mm_storeu_si128((key_schedule.cast::<__m128i>()).add(0), k1);
    _mm_storeu_si128((key_schedule.cast::<__m128i>()).add(ROUNDS), k0);

    for i in 1..ROUNDS / 2 {
        k0 = _mm_aesimc_si128(_mm_loadu_si128(key_schedule.cast::<__m128i>().add(i)));
        k1 = _mm_aesimc_si128(_mm_loadu_si128(
            key_schedule.cast::<__m128i>().add(ROUNDS - i),
        ));
        _mm_storeu_si128((key_schedule.cast::<__m128i>()).add(i), k1);
        _mm_storeu_si128((key_schedule.cast::<__m128i>()).add(ROUNDS - i), k0);
    }

    k0 = _mm_aesimc_si128(_mm_loadu_si128(
        key_schedule.cast::<__m128i>().add(ROUNDS / 2),
    ));
    _mm_storeu_si128((key_schedule.cast::<__m128i>()).add(ROUNDS / 2), k0);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes128_inverse_key(key_schedule: *mut u8) { inverse_key::<10>(key_schedule); }

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes192_inverse_key(key_schedule: *mut u8) { inverse_key::<12>(key_schedule); }

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes256_inverse_key(key_schedule: *mut u8) { inverse_key::<14>(key_schedule); }

#[cfg(test)]
mod tests
{
    use oxicrypt_test::Aes;
    use oxicrypt_test::AesVectorsIterator;

    use super::*;

    #[test]
    fn aes128()
    {
        for vectors in AesVectorsIterator::<{ Aes::Aes128 }>::new() {
            let mut key_schedule = vectors.expanded_key;
            unsafe { aes128_inverse_key(key_schedule.as_mut_ptr()) };
            assert_eq!(key_schedule, vectors.inversed_key);
        }
    }

    #[test]
    fn aes192()
    {
        for vectors in AesVectorsIterator::<{ Aes::Aes192 }>::new() {
            let mut key_schedule = vectors.expanded_key;
            unsafe { aes192_inverse_key(key_schedule.as_mut_ptr()) };
            assert_eq!(key_schedule, vectors.inversed_key);
        }
    }

    #[test]
    fn aes256()
    {
        for vectors in AesVectorsIterator::<{ Aes::Aes256 }>::new() {
            let mut key_schedule = vectors.expanded_key;
            unsafe { aes256_inverse_key(key_schedule.as_mut_ptr()) };
            assert_eq!(key_schedule, vectors.inversed_key);
        }
    }
}
