#[inline(always)]
pub unsafe fn aes128_expand_encrypt_key_generic(_key: *const u8, _round_keys: *mut u8) {}

#[inline(always)]
pub unsafe fn aes128_encrypt_generic(_block: *mut u8, _round_keys: *const u8) {}
