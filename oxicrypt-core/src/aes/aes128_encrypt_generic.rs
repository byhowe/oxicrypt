#[inline(always)]
pub unsafe fn aes128_expand_encrypt_key_generic(key: *const u8, round_keys: *mut u8) {}

#[inline(always)]
pub unsafe fn aes128_encrypt_generic(block: *mut u8, round_keys: *const u8) {}

#[inline(always)]
pub unsafe fn aes128_encrypt8_generic(blocks: *mut u8, round_keys: *const u8) {}
