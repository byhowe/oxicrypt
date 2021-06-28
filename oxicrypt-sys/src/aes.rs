use oxicrypt_core::aes::Variant;
use oxicrypt_core::aes::Implementation;

// Type definitions.

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_aes128_ctx_t
{
  round_keys: [u8; 176],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_aes192_ctx_t
{
  round_keys: [u8; 208],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_aes256_ctx_t
{
  round_keys: [u8; 240],
}

// Init functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_init(ctx: *mut oxi_aes128_ctx_t)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  ctx.round_keys = [0; 176];
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_init(ctx: *mut oxi_aes192_ctx_t)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  ctx.round_keys = [0; 208];
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_init(ctx: *mut oxi_aes256_ctx_t)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  ctx.round_keys = [0; 240];
}

// Set key functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_encrypt_key(ctx: *mut oxi_aes128_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  Implementation::expand_key::<{ Variant::Aes128 }>(Implementation::best())(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_encrypt_key(ctx: *mut oxi_aes192_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  Implementation::expand_key::<{ Variant::Aes192 }>(Implementation::best())(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_encrypt_key(ctx: *mut oxi_aes256_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  Implementation::expand_key::<{ Variant::Aes256 }>(Implementation::best())(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_decrypt_key(ctx: *mut oxi_aes128_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  Implementation::expand_key::<{ Variant::Aes128 }>(Implementation::best())(key, ctx.round_keys.as_mut_ptr());
  Implementation::inverse_key::<{ Variant::Aes128 }>(Implementation::best())(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_decrypt_key(ctx: *mut oxi_aes192_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  Implementation::expand_key::<{ Variant::Aes192 }>(Implementation::best())(key, ctx.round_keys.as_mut_ptr());
  Implementation::inverse_key::<{ Variant::Aes192 }>(Implementation::best())(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_decrypt_key(ctx: *mut oxi_aes256_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  Implementation::expand_key::<{ Variant::Aes256 }>(Implementation::best())(key, ctx.round_keys.as_mut_ptr());
  Implementation::inverse_key::<{ Variant::Aes256 }>(Implementation::best())(ctx.round_keys.as_mut_ptr());
}

// Inverse key functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key(ctx: *mut oxi_aes128_ctx_t)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  Implementation::inverse_key::<{ Variant::Aes128 }>(Implementation::best())(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key(ctx: *mut oxi_aes192_ctx_t)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  Implementation::inverse_key::<{ Variant::Aes192 }>(Implementation::best())(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key(ctx: *mut oxi_aes256_ctx_t)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  Implementation::inverse_key::<{ Variant::Aes256 }>(Implementation::best())(ctx.round_keys.as_mut_ptr());
}

// Encrypt functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt(ctx: *mut oxi_aes128_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  Implementation::encrypt::<{ Variant::Aes128 }>(Implementation::best())(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt(ctx: *mut oxi_aes192_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  Implementation::encrypt::<{ Variant::Aes192 }>(Implementation::best())(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt(ctx: *mut oxi_aes256_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  Implementation::encrypt::<{ Variant::Aes256 }>(Implementation::best())(block, ctx.round_keys.as_ptr());
}

// Decrypt functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt(ctx: *mut oxi_aes128_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  Implementation::decrypt::<{ Variant::Aes128 }>(Implementation::best())(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt(ctx: *mut oxi_aes192_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  Implementation::decrypt::<{ Variant::Aes192 }>(Implementation::best())(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt(ctx: *mut oxi_aes256_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  Implementation::decrypt::<{ Variant::Aes256 }>(Implementation::best())(block, ctx.round_keys.as_ptr());
}
