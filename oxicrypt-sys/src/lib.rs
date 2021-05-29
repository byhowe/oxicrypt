#![no_std]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(test))]
#[panic_handler]
fn panic(_panic: &core::panic::PanicInfo<'_>) -> !
{
  loop {}
}

/// See [`oxicrypt_core::aes::aes128_expand_encrypt_key_x86_aesni`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_expand_encrypt_key_x86_aesni(key: *const u8, round_keys: *mut u8)
{
  oxicrypt_core::aes::aes128_expand_encrypt_key_x86_aesni(key, round_keys);
}

/// See [`oxicrypt_core::aes::aes128_encrypt_x86_aesni`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt_x86_aesni(block: *mut u8, round_keys: *const u8)
{
  oxicrypt_core::aes::aes128_encrypt_x86_aesni(block, round_keys);
}

/// See [`oxicrypt_core::aes::aes128_encrypt8_x86_aesni`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt8_x86_aesni(blocks: *mut u8, round_keys: *const u8)
{
  oxicrypt_core::aes::aes128_encrypt8_x86_aesni(blocks, round_keys);
}

/// See [`oxicrypt_core::aes::aes128_expand_decrypt_key_x86_aesni`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_expand_decrypt_key_x86_aesni(key: *const u8, round_keys: *mut u8)
{
  oxicrypt_core::aes::aes128_expand_decrypt_key_x86_aesni(key, round_keys);
}

/// See [`oxicrypt_core::aes::aes128_decrypt_x86_aesni`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt_x86_aesni(block: *mut u8, round_keys: *const u8)
{
  oxicrypt_core::aes::aes128_decrypt_x86_aesni(block, round_keys);
}

/// See [`oxicrypt_core::aes::aes128_decrypt8_x86_aesni`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt8_x86_aesni(blocks: *mut u8, round_keys: *const u8)
{
  oxicrypt_core::aes::aes128_decrypt8_x86_aesni(blocks, round_keys);
}

/// See [`oxicrypt_core::sha::sha1_compress_generic`].
#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_compress_generic(state: *mut u32, block: *const u8)
{
  oxicrypt_core::sha::sha1_compress_generic(state, block);
}

/// See [`oxicrypt_core::sha::sha256_compress_generic`].
#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_compress_generic(state: *mut u32, block: *const u8)
{
  oxicrypt_core::sha::sha256_compress_generic(state, block);
}

/// See [`oxicrypt_core::sha::sha256_compress_generic`].
#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_compress_generic(state: *mut u64, block: *const u8)
{
  oxicrypt_core::sha::sha512_compress_generic(state, block);
}
