use oxicrypt_core::aes::AES128;
use oxicrypt_core::aes::AES192;
use oxicrypt_core::aes::AES256;

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

impl Default for oxi_aes128_ctx_t
{
  #[inline(always)]
  fn default() -> Self
  {
    Self { round_keys: [0; 176] }
  }
}

impl Default for oxi_aes192_ctx_t
{
  #[inline(always)]
  fn default() -> Self
  {
    Self { round_keys: [0; 208] }
  }
}

impl Default for oxi_aes256_ctx_t
{
  #[inline(always)]
  fn default() -> Self
  {
    Self { round_keys: [0; 240] }
  }
}

// Set key functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_encrypt_key(ctx: *mut oxi_aes128_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  AES128.expand_key(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_encrypt_key(ctx: *mut oxi_aes192_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  AES192.expand_key(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_encrypt_key(ctx: *mut oxi_aes256_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  AES256.expand_key(key, ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_decrypt_key(ctx: *mut oxi_aes128_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  AES128.expand_key(key, ctx.round_keys.as_mut_ptr());
  AES128.inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_decrypt_key(ctx: *mut oxi_aes192_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  AES192.expand_key(key, ctx.round_keys.as_mut_ptr());
  AES192.inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_decrypt_key(ctx: *mut oxi_aes256_ctx_t, key: *const u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  AES256.expand_key(key, ctx.round_keys.as_mut_ptr());
  AES256.inverse_key(ctx.round_keys.as_mut_ptr());
}

// Inverse key functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key(ctx: *mut oxi_aes128_ctx_t)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  AES128.inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key(ctx: *mut oxi_aes192_ctx_t)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  AES192.inverse_key(ctx.round_keys.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key(ctx: *mut oxi_aes256_ctx_t)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  AES256.inverse_key(ctx.round_keys.as_mut_ptr());
}

// Encrypt functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt(ctx: *mut oxi_aes128_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  AES128.encrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt(ctx: *mut oxi_aes192_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  AES192.encrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt(ctx: *mut oxi_aes256_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  AES256.encrypt(block, ctx.round_keys.as_ptr());
}

// Decrypt functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt(ctx: *mut oxi_aes128_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes128_ctx_t = &mut *ctx;
  AES128.decrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt(ctx: *mut oxi_aes192_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes192_ctx_t = &mut *ctx;
  AES192.decrypt(block, ctx.round_keys.as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt(ctx: *mut oxi_aes256_ctx_t, block: *mut u8)
{
  let ctx: &mut oxi_aes256_ctx_t = &mut *ctx;
  AES256.decrypt(block, ctx.round_keys.as_ptr());
}
