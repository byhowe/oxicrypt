use oxicrypt_core::aes_lut;

// AES-128 ENCRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes128_encrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_lut::aes128_encrypt1(block, key_schedule);
}

// AES-192 ENCRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes192_encrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_lut::aes192_encrypt1(block, key_schedule);
}

// AES-256 ENCRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes256_encrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_lut::aes256_encrypt1(block, key_schedule);
}

// AES-128 DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes128_decrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_lut::aes128_decrypt1(block, key_schedule);
}

// AES-192 DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes192_decrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_lut::aes192_decrypt1(block, key_schedule);
}

// AES-256 DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes256_decrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_lut::aes256_decrypt1(block, key_schedule);
}

// AES EXPAND KEY
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes128_expand_key(key: *const u8, key_schedule: *mut u8)
{
    aes_lut::aes128_expand_key(key, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes192_expand_key(key: *const u8, key_schedule: *mut u8)
{
    aes_lut::aes192_expand_key(key, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes256_expand_key(key: *const u8, key_schedule: *mut u8)
{
    aes_lut::aes256_expand_key(key, key_schedule);
}

// AES INVERSE KEY
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes128_inverse_key(key_schedule: *mut u8)
{
    aes_lut::aes128_inverse_key(key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes192_inverse_key(key_schedule: *mut u8)
{
    aes_lut::aes192_inverse_key(key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_lut_aes256_inverse_key(key_schedule: *mut u8)
{
    aes_lut::aes256_inverse_key(key_schedule);
}
