#[inline(always)]
pub unsafe fn aes128_expand_decrypt_key_generic(key: *const u8, round_keys: *mut u8) {}

#[inline(always)]
pub unsafe fn aes128_decrypt_generic(block: *mut u8, round_key: *const u8) {}

#[inline(always)]
pub unsafe fn aes128_decrypt8_generic(blocks: *mut u8, round_key: *const u8) {}
