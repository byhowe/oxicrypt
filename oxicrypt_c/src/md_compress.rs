use oxicrypt_core::md_compress;

#[no_mangle]
pub unsafe extern "C" fn oxi_digest_compress_md5(state: *mut u32, block: *const u8)
{
    md_compress::md5(state, block);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_digest_compress_sha1(state: *mut u32, block: *const u8)
{
    md_compress::sha1(state, block);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_digest_compress_sha256(state: *mut u32, block: *const u8)
{
    md_compress::sha256(state, block);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_digest_compress_sha512(state: *mut u64, block: *const u8)
{
    md_compress::sha512(state, block);
}
