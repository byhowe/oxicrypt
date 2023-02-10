use oxicrypt_core::aes_arm;

// AES-128 ENCRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_encrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_encrypt1(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_encrypt2(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_encrypt2(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_encrypt4(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_encrypt4(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_encrypt8(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_encrypt8(block, key_schedule);
}

// AES-192 ENCRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_encrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_encrypt1(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_encrypt2(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_encrypt2(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_encrypt4(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_encrypt4(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_encrypt8(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_encrypt8(block, key_schedule);
}

// AES-256 ENCRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_encrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_encrypt1(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_encrypt2(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_encrypt2(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_encrypt4(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_encrypt4(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_encrypt8(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_encrypt8(block, key_schedule);
}

// AES-128 DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_decrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_decrypt1(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_decrypt2(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_decrypt2(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_decrypt4(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_decrypt4(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes128_decrypt8(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes128_decrypt8(block, key_schedule);
}

// AES-192 DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_decrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_decrypt1(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_decrypt2(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_decrypt2(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_decrypt4(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_decrypt4(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes192_decrypt8(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes192_decrypt8(block, key_schedule);
}

// AES-256 DECRYPT
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_decrypt1(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_decrypt1(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_decrypt2(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_decrypt2(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_decrypt4(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_decrypt4(block, key_schedule);
}
#[no_mangle]
pub unsafe extern "C" fn oxi_core_aes_arm_aes256_decrypt8(block: *mut u8, key_schedule: *const u8)
{
    aes_arm::aes256_decrypt8(block, key_schedule);
}
