use oxicrypt_core::aes::Aes;
use oxicrypt_core::aes::Control;
use oxicrypt_core::aes::Variant;

// Type definitions.

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_aes128_ctx_t
{
  aes: *const Aes,
  round_keys: [u8; 176],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_aes192_ctx_t
{
  aes: *const Aes,
  round_keys: [u8; 208],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_aes256_ctx_t
{
  aes: *const Aes,
  round_keys: [u8; 240],
}

// Init functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_init(ctx: *mut oxi_aes128_ctx_t)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  ctx.aes = Control::best_impl(Variant::Aes128);
  ctx.round_keys = [0; 176];
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_init(ctx: *mut oxi_aes192_ctx_t)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  ctx.aes = Control::best_impl(Variant::Aes192);
  ctx.round_keys = [0; 208];
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_init(ctx: *mut oxi_aes256_ctx_t)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  ctx.aes = Control::best_impl(Variant::Aes256);
  ctx.round_keys = [0; 240];
}

// Set key functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_encrypt_key(ctx: *mut oxi_aes128_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  (&*ctx.aes).expand_key(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_encrypt_key(ctx: *mut oxi_aes192_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  (&*ctx.aes).expand_key(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_encrypt_key(ctx: *mut oxi_aes256_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  (&*ctx.aes).expand_key(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_decrypt_key(ctx: *mut oxi_aes128_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  (&*ctx.aes).expand_key(key, ctx.round_keys.as_mut_ptr());
  (&*ctx.aes).inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_decrypt_key(ctx: *mut oxi_aes192_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  (&*ctx.aes).expand_key(key, ctx.round_keys.as_mut_ptr());
  (&*ctx.aes).inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_decrypt_key(ctx: *mut oxi_aes256_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  (&*ctx.aes).expand_key(key, ctx.round_keys.as_mut_ptr());
  (&*ctx.aes).inverse_key(ctx.round_keys.as_mut_ptr());
}

// Inverse key functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key(ctx: *mut oxi_aes128_ctx_t)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  (&*ctx.aes).inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key(ctx: *mut oxi_aes192_ctx_t)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  (&*ctx.aes).inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key(ctx: *mut oxi_aes256_ctx_t)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  (&*ctx.aes).inverse_key(ctx.round_keys.as_mut_ptr());
}

// Encrypt functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt(ctx: *mut oxi_aes128_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  (&*ctx.aes).encrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt(ctx: *mut oxi_aes192_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  (&*ctx.aes).encrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt(ctx: *mut oxi_aes256_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  (&*ctx.aes).encrypt(block, ctx.round_keys.as_ptr());
}

// Decrypt functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt(ctx: *mut oxi_aes128_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  (&*ctx.aes).decrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt(ctx: *mut oxi_aes192_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  (&*ctx.aes).decrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt(ctx: *mut oxi_aes256_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  (&*ctx.aes).decrypt(block, ctx.round_keys.as_ptr());
}
