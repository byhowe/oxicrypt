#![no_std]

use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> !
{
  loop {}
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
