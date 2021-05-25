/// See [`oxicrypt::sha::sha1_compress_generic`].
#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_compress_generic(state: *mut u32, block: *const u8)
{
  oxicrypt::sha::sha1_compress_generic(state, block);
}

/// See [`oxicrypt::sha::sha256_compress_generic`].
#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_compress_generic(state: *mut u32, block: *const u8)
{
  oxicrypt::sha::sha256_compress_generic(state, block);
}

/// See [`oxicrypt::sha::sha256_compress_generic`].
#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_compress_generic(state: *mut u64, block: *const u8)
{
  oxicrypt::sha::sha512_compress_generic(state, block);
}
