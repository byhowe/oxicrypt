#![allow(clippy::missing_safety_doc)]

use alloc::boxed::Box;
use core::slice;

use oxicrypt::aes::Key128;
use oxicrypt::aes::Key192;
use oxicrypt::aes::Key256;

// Key schedules
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_new() -> Box<Key128> { Box::new_uninit().assume_init() }
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_new() -> Box<Key192> { Box::new_uninit().assume_init() }
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_new() -> Box<Key256> { Box::new_uninit().assume_init() }

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_drop(_ctx: Option<Box<Key128>>) {}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_drop(_ctx: Option<Box<Key192>>) {}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_drop(_ctx: Option<Box<Key256>>) {}

// AES SET ENCRYPT KEY
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_encrypt_key(ctx: &mut Key128, key: *const u8)
{
    ctx.set_encrypt_key_unchecked(slice::from_raw_parts(key, Key128::KEY_LEN));
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_encrypt_key(ctx: &mut Key192, key: *const u8)
{
    ctx.set_encrypt_key_unchecked(slice::from_raw_parts(key, Key192::KEY_LEN));
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_encrypt_key(ctx: &mut Key256, key: *const u8)
{
    ctx.set_encrypt_key_unchecked(slice::from_raw_parts(key, Key256::KEY_LEN));
}

// AES SET DECRYPT KEY
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_decrypt_key(ctx: &mut Key128, key: *const u8)
{
    ctx.set_decrypt_key_unchecked(slice::from_raw_parts(key, Key128::KEY_LEN));
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_decrypt_key(ctx: &mut Key192, key: *const u8)
{
    ctx.set_decrypt_key_unchecked(slice::from_raw_parts(key, Key192::KEY_LEN));
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_decrypt_key(ctx: &mut Key256, key: *const u8)
{
    ctx.set_decrypt_key_unchecked(slice::from_raw_parts(key, Key256::KEY_LEN));
}

// AES INVERSE KEY
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key(ctx: &mut Key128) { ctx.inverse_key(); }
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key(ctx: &mut Key192) { ctx.inverse_key(); }
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key(ctx: &mut Key256) { ctx.inverse_key(); }

// AES ENCRYPT/DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt(ctx: &Key128, block: *mut u8, blocklen: usize)
{
    ctx.encrypt_unchecked(slice::from_raw_parts_mut(block, blocklen * 16))
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt(ctx: &Key192, block: *mut u8, blocklen: usize)
{
    ctx.encrypt_unchecked(slice::from_raw_parts_mut(block, blocklen * 16))
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt(ctx: &Key256, block: *mut u8, blocklen: usize)
{
    ctx.encrypt_unchecked(slice::from_raw_parts_mut(block, blocklen * 16))
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt(ctx: &Key128, block: *mut u8, blocklen: usize)
{
    ctx.decrypt_unchecked(slice::from_raw_parts_mut(block, blocklen * 16))
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt(ctx: &Key192, block: *mut u8, blocklen: usize)
{
    ctx.decrypt_unchecked(slice::from_raw_parts_mut(block, blocklen * 16))
}
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt(ctx: &Key256, block: *mut u8, blocklen: usize)
{
    ctx.decrypt_unchecked(slice::from_raw_parts_mut(block, blocklen * 16))
}
