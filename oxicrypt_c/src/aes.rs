#![allow(clippy::missing_safety_doc)]

use core::slice;

use oxicrypt::aes::Key128;
use oxicrypt::aes::Key192;
use oxicrypt::aes::Key256;
use oxicrypt::aes::Variant;
use oxicrypt::hazmat::aes;
use oxicrypt::Implementation;

use crate::oxi_implementation_t;

// Raw AES functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_expand_key_lut(key: *const u8, key_schedule: *mut u8)
{
  aes::lut::aes128_expand_key(key, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key_lut(key_schedule: *mut u8)
{
  aes::lut::aes128_inverse_key(key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt1_lut(block: *mut u8, key_schedule: *const u8)
{
  aes::lut::aes128_encrypt1(block, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt1_lut(block: *mut u8, key_schedule: *const u8)
{
  aes::lut::aes128_decrypt1(block, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_expand_key_lut(key: *const u8, key_schedule: *mut u8)
{
  aes::lut::aes192_expand_key(key, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key_lut(key_schedule: *mut u8)
{
  aes::lut::aes192_inverse_key(key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt1_lut(block: *mut u8, key_schedule: *const u8)
{
  aes::lut::aes192_encrypt1(block, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt1_lut(block: *mut u8, key_schedule: *const u8)
{
  aes::lut::aes192_decrypt1(block, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_expand_key_lut(key: *const u8, key_schedule: *mut u8)
{
  aes::lut::aes256_expand_key(key, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key_lut(key_schedule: *mut u8)
{
  aes::lut::aes256_inverse_key(key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt1_lut(block: *mut u8, key_schedule: *const u8)
{
  aes::lut::aes256_encrypt1(block, key_schedule);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt1_lut(block: *mut u8, key_schedule: *const u8)
{
  aes::lut::aes256_decrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_expand_key_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes::aesni::aes128_expand_key(key, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key_aesni(key_schedule: *mut u8)
{
  aes::aesni::aes128_inverse_key(key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_encrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt2_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_encrypt2(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt4_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_encrypt4(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt8_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_encrypt8(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_decrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt2_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_decrypt2(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt4_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_decrypt4(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt8_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_decrypt8(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_expand_key_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes::aesni::aes192_expand_key(key, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key_aesni(key_schedule: *mut u8)
{
  aes::aesni::aes192_inverse_key(key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_encrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt2_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_encrypt2(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt4_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_encrypt4(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt8_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_encrypt8(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_decrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt2_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_decrypt2(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt4_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_decrypt4(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt8_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_decrypt8(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_expand_key_aesni(key: *const u8, key_schedule: *mut u8)
{
  aes::aesni::aes256_expand_key(key, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key_aesni(key_schedule: *mut u8)
{
  aes::aesni::aes256_inverse_key(key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_encrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt2_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_encrypt2(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt4_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_encrypt4(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt8_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_encrypt8(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_decrypt1(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt2_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_decrypt2(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt4_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_decrypt4(block, key_schedule);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "aes")]
#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt8_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_decrypt8(block, key_schedule);
}

// Key schedules.

#[allow(non_camel_case_types)]
pub type oxi_aes128_key_t = Key128;

#[allow(non_camel_case_types)]
pub type oxi_aes192_key_t = Key192;

#[allow(non_camel_case_types)]
pub type oxi_aes256_key_t = Key256;

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_encrypt_key(
  ctx: *mut oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  key: *const u8,
)
{
  let ctx = &mut *ctx;
  ctx.set_encrypt_key_unchecked(
    implementation,
    slice::from_raw_parts(key, Variant::key_len(Variant::Aes128)),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_set_decrypt_key(
  ctx: *mut oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  key: *const u8,
)
{
  let ctx = &mut *ctx;
  ctx.set_decrypt_key_unchecked(
    implementation,
    slice::from_raw_parts(key, Variant::key_len(Variant::Aes128)),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_inverse_key(ctx: *mut oxi_aes128_key_t, implementation: oxi_implementation_t)
{
  let ctx = &mut *ctx;
  ctx.inverse_key(implementation);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
  blocklen: usize,
)
{
  let ctx = &*ctx;
  ctx.encrypt_unchecked(implementation, slice::from_raw_parts_mut(block, blocklen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt1(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt2(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt2_unchecked(implementation, slice::from_raw_parts_mut(block, 32));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt4(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt4_unchecked(implementation, slice::from_raw_parts_mut(block, 64));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_encrypt8(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt8_unchecked(implementation, slice::from_raw_parts_mut(block, 128));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
  blocklen: usize,
)
{
  let ctx = &*ctx;
  ctx.decrypt_unchecked(implementation, slice::from_raw_parts_mut(block, blocklen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt1(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt2(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt2_unchecked(implementation, slice::from_raw_parts_mut(block, 32));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt4(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt4_unchecked(implementation, slice::from_raw_parts_mut(block, 64));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_decrypt8(
  ctx: *const oxi_aes128_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt8_unchecked(implementation, slice::from_raw_parts_mut(block, 128));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_encrypt_key(
  ctx: *mut oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  key: *const u8,
)
{
  let ctx = &mut *ctx;
  ctx.set_encrypt_key_unchecked(
    implementation,
    slice::from_raw_parts(key, Variant::key_len(Variant::Aes192)),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_set_decrypt_key(
  ctx: *mut oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  key: *const u8,
)
{
  let ctx = &mut *ctx;
  ctx.set_decrypt_key_unchecked(
    implementation,
    slice::from_raw_parts(key, Variant::key_len(Variant::Aes192)),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_inverse_key(ctx: *mut oxi_aes192_key_t, implementation: oxi_implementation_t)
{
  let ctx = &mut *ctx;
  ctx.inverse_key(implementation);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
  blocklen: usize,
)
{
  let ctx = &*ctx;
  ctx.encrypt_unchecked(implementation, slice::from_raw_parts_mut(block, blocklen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt1(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt2(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt2_unchecked(implementation, slice::from_raw_parts_mut(block, 32));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt4(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt4_unchecked(implementation, slice::from_raw_parts_mut(block, 64));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_encrypt8(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt8_unchecked(implementation, slice::from_raw_parts_mut(block, 192));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
  blocklen: usize,
)
{
  let ctx = &*ctx;
  ctx.decrypt_unchecked(implementation, slice::from_raw_parts_mut(block, blocklen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt1(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt2(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt2_unchecked(implementation, slice::from_raw_parts_mut(block, 32));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt4(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt4_unchecked(implementation, slice::from_raw_parts_mut(block, 64));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_decrypt8(
  ctx: *const oxi_aes192_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt8_unchecked(implementation, slice::from_raw_parts_mut(block, 192));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_encrypt_key(
  ctx: *mut oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  key: *const u8,
)
{
  let ctx = &mut *ctx;
  ctx.set_encrypt_key_unchecked(
    implementation,
    slice::from_raw_parts(key, Variant::key_len(Variant::Aes256)),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_set_decrypt_key(
  ctx: *mut oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  key: *const u8,
)
{
  let ctx = &mut *ctx;
  ctx.set_decrypt_key_unchecked(
    implementation,
    slice::from_raw_parts(key, Variant::key_len(Variant::Aes256)),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_inverse_key(ctx: *mut oxi_aes256_key_t, implementation: oxi_implementation_t)
{
  let ctx = &mut *ctx;
  ctx.inverse_key(implementation);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
  blocklen: usize,
)
{
  let ctx = &*ctx;
  ctx.encrypt_unchecked(implementation, slice::from_raw_parts_mut(block, blocklen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt1(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt2(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt2_unchecked(implementation, slice::from_raw_parts_mut(block, 32));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt4(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt4_unchecked(implementation, slice::from_raw_parts_mut(block, 64));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_encrypt8(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.encrypt8_unchecked(implementation, slice::from_raw_parts_mut(block, 128));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
  blocklen: usize,
)
{
  let ctx = &*ctx;
  ctx.decrypt_unchecked(implementation, slice::from_raw_parts_mut(block, blocklen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt1(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt2(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt2_unchecked(implementation, slice::from_raw_parts_mut(block, 32));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt4(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt4_unchecked(implementation, slice::from_raw_parts_mut(block, 64));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_decrypt8(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt8_unchecked(implementation, slice::from_raw_parts_mut(block, 128));
}
