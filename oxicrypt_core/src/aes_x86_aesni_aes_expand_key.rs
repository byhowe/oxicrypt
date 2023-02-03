#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", doc)))]
compile_error!("`aes_x86_aesni_aes_expand_key` module is only available for `x86` and `x86_64`");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn expand_round<const IMM8: i32>(mut k: __m128i, mut kr: __m128i) -> __m128i
{
    kr = _mm_shuffle_epi32::<IMM8>(kr);
    k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
    k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
    k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
    _mm_xor_si128(k, kr)
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes128_expand_key(key: *const u8, key_schedule: *mut u8)
{
    let mut k: __m128i = _mm_loadu_si128(key.cast::<__m128i>());
    _mm_storeu_si128(key_schedule.cast::<__m128i>(), k);

    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x01>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(1), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x02>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(2), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x04>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(3), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x08>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(4), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x10>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(5), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x20>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(6), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x40>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(7), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x80>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(8), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x1b>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(9), k);
    k = expand_round::<0xff>(k, _mm_aeskeygenassist_si128::<0x36>(k));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(10), k);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes192_expand_key(key: *const u8, key_schedule: *mut u8)
{
    #[inline(always)]
    unsafe fn expand_round_half(mut k1: __m128i, k0: __m128i) -> __m128i
    {
        k1 = _mm_xor_si128(k1, _mm_slli_si128::<4>(k1));
        _mm_xor_si128(k1, _mm_shuffle_epi32::<0xff>(k0))
    }

    let mut k0: __m128i = _mm_loadu_si128(key.add(0).cast::<__m128i>());
    let mut k1: __m128i = _mm_loadu_si128(key.add(8).cast::<__m128i>());
    k1 = _mm_srli_si128::<8>(k1);
    _mm_storeu_si128(key_schedule.add(0).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(16).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x01>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(24).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(40).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x02>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(48).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(64).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x04>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(72).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(88).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x08>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(96).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(112).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x10>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(120).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(136).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x20>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(144).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(160).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x40>(k1));
    k1 = expand_round_half(k1, k0);
    _mm_storeu_si128(key_schedule.add(168).cast::<__m128i>(), k0);
    _mm_storeu_si128(key_schedule.add(184).cast::<__m128i>(), k1);

    k0 = expand_round::<0x55>(k0, _mm_aeskeygenassist_si128::<0x80>(k1));
    _mm_storeu_si128(key_schedule.add(192).cast::<__m128i>(), k0);
}

#[target_feature(enable = "aes")]
#[doc(cfg(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn aes_x86_aesni_aes256_expand_key(key: *const u8, key_schedule: *mut u8)
{
    let mut k0: __m128i = _mm_loadu_si128((key.cast::<__m128i>()).add(0));
    let mut k1: __m128i = _mm_loadu_si128((key.cast::<__m128i>()).add(1));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(0), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(1), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x01>(k1));
    k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(2), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(3), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x02>(k1));
    k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(4), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(5), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x04>(k1));
    k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(6), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(7), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x08>(k1));
    k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(8), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(9), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x10>(k1));
    k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(10), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(11), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x20>(k1));
    k1 = expand_round::<0xaa>(k1, _mm_aeskeygenassist_si128::<0x00>(k0));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(12), k0);
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(13), k1);

    k0 = expand_round::<0xff>(k0, _mm_aeskeygenassist_si128::<0x40>(k1));
    _mm_storeu_si128(key_schedule.cast::<__m128i>().add(14), k0);
}

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
            let mut key_schedule = [0; 176];
            unsafe {
                aes_x86_aesni_aes128_expand_key(vectors.key.as_ptr(), key_schedule.as_mut_ptr())
            };
            assert_eq!(key_schedule, vectors.expanded_key);
        }
    }

    #[test]
    fn aes192()
    {
        for vectors in AesVectorsIterator::<{ Aes::Aes192 }>::new() {
            let mut key_schedule = [0; 208];
            unsafe {
                aes_x86_aesni_aes192_expand_key(vectors.key.as_ptr(), key_schedule.as_mut_ptr())
            };
            assert_eq!(key_schedule, vectors.expanded_key);
        }
    }

    #[test]
    fn aes256()
    {
        for vectors in AesVectorsIterator::<{ Aes::Aes256 }>::new() {
            let mut key_schedule = [0; 240];
            unsafe {
                aes_x86_aesni_aes256_expand_key(vectors.key.as_ptr(), key_schedule.as_mut_ptr())
            };
            assert_eq!(key_schedule, vectors.expanded_key);
        }
    }
}
