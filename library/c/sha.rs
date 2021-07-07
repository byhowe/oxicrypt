#![allow(clippy::missing_safety_doc)]

use core::slice;

use crate::crypto::sha::Implementation;
use crate::crypto::sha::Sha;
use crate::crypto::sha::Variant;
use crate::sha::Sha as ShaCtx;

// Raw SHA functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha1 }, { Implementation::Generic }>::compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha224 }, { Implementation::Generic }>::compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha256 }, { Implementation::Generic }>::compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha384 }, { Implementation::Generic }>::compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha512 }, { Implementation::Generic }>::compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha512_224 }, { Implementation::Generic }>::compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_compress_generic(state: *mut u8, block: *const u8)
{
  Sha::<{ Variant::Sha512_256 }, { Implementation::Generic }>::compress(state, block);
}

// Implementations.

#[allow(non_camel_case_types)]
pub type oxi_sha_implementation_t = Implementation;

#[no_mangle]
pub unsafe extern "C" fn oxi_sha_implementation_fastest() -> oxi_sha_implementation_t
{
  oxi_sha_implementation_t::fastest()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha_implementation_fastest_rt() -> oxi_sha_implementation_t
{
  oxi_sha_implementation_t::fastest_rt()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha_implementation_is_available(implementation: oxi_sha_implementation_t) -> bool
{
  oxi_sha_implementation_t::is_available(implementation)
}

// Engine.

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct oxi_sha_engine_t
{
  compress: unsafe extern "C" fn(*mut u8, *const u8),
}

impl oxi_sha_engine_t
{
  const E1_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha1 }>(Implementation::Generic) };
  const E224_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha224 }>(Implementation::Generic) };
  const E256_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha256 }>(Implementation::Generic) };
  const E384_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha384 }>(Implementation::Generic) };
  const E512_224_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha512_224 }>(Implementation::Generic) };
  const E512_256_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha512_256 }>(Implementation::Generic) };
  const E512_GENERIC: Self = unsafe { Self::new::<{ Variant::Sha512 }>(Implementation::Generic) };

  const unsafe fn new<const V: Variant>(implementation: Implementation) -> Self
  {
    match implementation {
      | Implementation::Generic => match V {
        | Variant::Sha1 => Self {
          compress: oxi_sha1_compress_generic,
        },
        | Variant::Sha224 => Self {
          compress: oxi_sha224_compress_generic,
        },
        | Variant::Sha256 => Self {
          compress: oxi_sha256_compress_generic,
        },
        | Variant::Sha384 => Self {
          compress: oxi_sha384_compress_generic,
        },
        | Variant::Sha512 => Self {
          compress: oxi_sha512_compress_generic,
        },
        | Variant::Sha512_224 => Self {
          compress: oxi_sha512_224_compress_generic,
        },
        | Variant::Sha512_256 => Self {
          compress: oxi_sha512_256_compress_generic,
        },
      },
    }
  }

  const unsafe fn as_ref<const V: Variant>(implementation: Implementation) -> &'static Self
  {
    match implementation {
      | Implementation::Generic => match V {
        | Variant::Sha1 => &Self::E1_GENERIC,
        | Variant::Sha224 => &Self::E224_GENERIC,
        | Variant::Sha256 => &Self::E256_GENERIC,
        | Variant::Sha384 => &Self::E384_GENERIC,
        | Variant::Sha512 => &Self::E512_GENERIC,
        | Variant::Sha512_224 => &Self::E512_224_GENERIC,
        | Variant::Sha512_256 => &Self::E512_256_GENERIC,
      },
    }
  }
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha1 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_engine_as_ref(implementation: oxi_sha_implementation_t) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha1 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha224 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_engine_as_ref(implementation: oxi_sha_implementation_t) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha224 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha256 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_engine_as_ref(implementation: oxi_sha_implementation_t) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha256 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha384 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_engine_as_ref(implementation: oxi_sha_implementation_t) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha384 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha512 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_engine_as_ref(implementation: oxi_sha_implementation_t) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha512 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha512_224 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_engine_as_ref(
  implementation: oxi_sha_implementation_t,
) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha512_224 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_engine_new(implementation: oxi_sha_implementation_t) -> oxi_sha_engine_t
{
  oxi_sha_engine_t::new::<{ Variant::Sha512_256 }>(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_engine_as_ref(
  implementation: oxi_sha_implementation_t,
) -> *const oxi_sha_engine_t
{
  oxi_sha_engine_t::as_ref::<{ Variant::Sha512_256 }>(implementation)
}

// SHA contexts.

#[allow(non_camel_case_types)]
pub type oxi_sha1_t = ShaCtx<{ Variant::Sha1 }>;

#[allow(non_camel_case_types)]
pub type oxi_sha224_t = ShaCtx<{ Variant::Sha224 }>;

#[allow(non_camel_case_types)]
pub type oxi_sha256_t = ShaCtx<{ Variant::Sha256 }>;

#[allow(non_camel_case_types)]
pub type oxi_sha384_t = ShaCtx<{ Variant::Sha384 }>;

#[allow(non_camel_case_types)]
pub type oxi_sha512_t = ShaCtx<{ Variant::Sha512 }>;

#[allow(non_camel_case_types)]
pub type oxi_sha512_224_t = ShaCtx<{ Variant::Sha512_224 }>;

#[allow(non_camel_case_types)]
pub type oxi_sha512_256_t = ShaCtx<{ Variant::Sha512_256 }>;

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_reset(ctx: *mut oxi_sha1_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_reset(ctx: *mut oxi_sha224_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_reset(ctx: *mut oxi_sha256_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_reset(ctx: *mut oxi_sha384_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_reset(ctx: *mut oxi_sha512_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_reset(ctx: *mut oxi_sha512_224_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_reset(ctx: *mut oxi_sha512_256_t)
{
  let ctx = &mut *ctx;
  ctx.reset();
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_update(
  ctx: *mut oxi_sha1_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_update(
  ctx: *mut oxi_sha224_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_update(
  ctx: *mut oxi_sha256_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_update(
  ctx: *mut oxi_sha384_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_update(
  ctx: *mut oxi_sha512_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_update(
  ctx: *mut oxi_sha512_224_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_update(
  ctx: *mut oxi_sha512_256_t,
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_finish(
  ctx: *mut oxi_sha1_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_finish(
  ctx: *mut oxi_sha224_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_finish(
  ctx: *mut oxi_sha256_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_finish(
  ctx: *mut oxi_sha384_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_finish(
  ctx: *mut oxi_sha512_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_finish(
  ctx: *mut oxi_sha512_224_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_finish(
  ctx: *mut oxi_sha512_256_t,
  implementation: oxi_sha_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha1 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha224 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha256 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha384 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha512 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha512_224 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_oneshot(
  implementation: oxi_sha_implementation_t,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  ShaCtx::<{ Variant::Sha512_256 }>::oneshot_into(
    implementation,
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}
