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
pub unsafe extern "C" fn oxi_aes128_decrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes128_decrypt1(block, key_schedule);
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
pub unsafe extern "C" fn oxi_aes192_decrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes192_decrypt1(block, key_schedule);
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
pub unsafe extern "C" fn oxi_aes256_decrypt1_aesni(block: *mut u8, key_schedule: *const u8)
{
  aes::aesni::aes256_decrypt1(block, key_schedule);
}

// Engine.

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct oxi_aes_engine_t
{
  expand_key: unsafe extern "C" fn(*const u8, *mut u8),
  inverse_key: unsafe extern "C" fn(*mut u8),
  encrypt1: unsafe extern "C" fn(*mut u8, *const u8),
  decrypt1: unsafe extern "C" fn(*mut u8, *const u8),
}

impl oxi_aes_engine_t
{
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E128_AESNI: Self = unsafe { Self::new(Variant::Aes128, Implementation::AES) };
  const E128_LUT: Self = unsafe { Self::new(Variant::Aes128, Implementation::new()) };
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E192_AESNI: Self = unsafe { Self::new(Variant::Aes192, Implementation::AES) };
  const E192_LUT: Self = unsafe { Self::new(Variant::Aes192, Implementation::new()) };
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  const E256_AESNI: Self = unsafe { Self::new(Variant::Aes256, Implementation::AES) };
  const E256_LUT: Self = unsafe { Self::new(Variant::Aes256, Implementation::new()) };

  const unsafe fn new(variant: Variant, implementation: Implementation) -> Self
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match variant {
        | Variant::Aes128 => Self {
          expand_key: oxi_aes128_expand_key_aesni,
          inverse_key: oxi_aes128_inverse_key_aesni,
          encrypt1: oxi_aes128_encrypt1_aesni,
          decrypt1: oxi_aes128_decrypt1_aesni,
        },
        | Variant::Aes192 => Self {
          expand_key: oxi_aes192_expand_key_aesni,
          inverse_key: oxi_aes192_inverse_key_aesni,
          encrypt1: oxi_aes192_encrypt1_aesni,
          decrypt1: oxi_aes192_decrypt1_aesni,
        },
        | Variant::Aes256 => Self {
          expand_key: oxi_aes256_expand_key_aesni,
          inverse_key: oxi_aes256_inverse_key_aesni,
          encrypt1: oxi_aes256_encrypt1_aesni,
          decrypt1: oxi_aes256_decrypt1_aesni,
        },
      },
      | _ => match variant {
        | Variant::Aes128 => Self {
          expand_key: oxi_aes128_expand_key_lut,
          inverse_key: oxi_aes128_inverse_key_lut,
          encrypt1: oxi_aes128_encrypt1_lut,
          decrypt1: oxi_aes128_decrypt1_lut,
        },
        | Variant::Aes192 => Self {
          expand_key: oxi_aes192_expand_key_lut,
          inverse_key: oxi_aes192_inverse_key_lut,
          encrypt1: oxi_aes192_encrypt1_lut,
          decrypt1: oxi_aes192_decrypt1_lut,
        },
        | Variant::Aes256 => Self {
          expand_key: oxi_aes256_expand_key_lut,
          inverse_key: oxi_aes256_inverse_key_lut,
          encrypt1: oxi_aes256_encrypt1_lut,
          decrypt1: oxi_aes256_decrypt1_lut,
        },
      },
    }
  }

  const unsafe fn as_ref(variant: Variant, implementation: Implementation) -> &'static Self
  {
    match implementation {
      #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
      | i if i.is_present(Implementation::AES) => match variant {
        | Variant::Aes128 => &Self::E128_AESNI,
        | Variant::Aes192 => &Self::E192_AESNI,
        | Variant::Aes256 => &Self::E256_AESNI,
      },
      | _ => match variant {
        | Variant::Aes128 => &Self::E128_LUT,
        | Variant::Aes192 => &Self::E192_LUT,
        | Variant::Aes256 => &Self::E256_LUT,
      },
    }
  }
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_engine_new(implementation: oxi_implementation_t) -> oxi_aes_engine_t
{
  oxi_aes_engine_t::new(Variant::Aes128, implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes128_engine_as_ref(implementation: oxi_implementation_t) -> *const oxi_aes_engine_t
{
  oxi_aes_engine_t::as_ref(Variant::Aes128, implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_engine_new(implementation: oxi_implementation_t) -> oxi_aes_engine_t
{
  oxi_aes_engine_t::new(Variant::Aes192, implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes192_engine_as_ref(implementation: oxi_implementation_t) -> *const oxi_aes_engine_t
{
  oxi_aes_engine_t::as_ref(Variant::Aes192, implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_engine_new(implementation: oxi_implementation_t) -> oxi_aes_engine_t
{
  oxi_aes_engine_t::new(Variant::Aes256, implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_aes256_engine_as_ref(implementation: oxi_implementation_t) -> *const oxi_aes_engine_t
{
  oxi_aes_engine_t::as_ref(Variant::Aes256, implementation)
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
pub unsafe extern "C" fn oxi_aes256_decrypt1(
  ctx: *const oxi_aes256_key_t,
  implementation: oxi_implementation_t,
  block: *mut u8,
)
{
  let ctx = &*ctx;
  ctx.decrypt1_unchecked(implementation, slice::from_raw_parts_mut(block, 16));
}
