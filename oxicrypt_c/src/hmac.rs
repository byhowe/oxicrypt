#![allow(clippy::missing_safety_doc)]

use core::slice;

use oxicrypt::hmac::HmacSha1;
use oxicrypt::hmac::HmacSha224;
use oxicrypt::hmac::HmacSha256;
use oxicrypt::hmac::HmacSha384;
use oxicrypt::hmac::HmacSha512;
use oxicrypt::hmac::HmacSha512_224;
use oxicrypt::hmac::HmacSha512_256;

use crate::oxi_implementation_t;

// HMAC contexts.

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha1_t = HmacSha1;

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha224_t = HmacSha224;

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha256_t = HmacSha256;

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha384_t = HmacSha384;

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha512_t = HmacSha512;

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha512_224_t = HmacSha512_224;

#[allow(non_camel_case_types)]
pub type oxi_hmac_sha512_256_t = HmacSha512_256;

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha1_set_key(
  ctx: *mut oxi_hmac_sha1_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha224_set_key(
  ctx: *mut oxi_hmac_sha224_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha256_set_key(
  ctx: *mut oxi_hmac_sha256_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha384_set_key(
  ctx: *mut oxi_hmac_sha384_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_set_key(
  ctx: *mut oxi_hmac_sha512_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_224_set_key(
  ctx: *mut oxi_hmac_sha512_224_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_256_set_key(
  ctx: *mut oxi_hmac_sha512_256_t,
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.set_key(implementation, slice::from_raw_parts(key, keylen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha1_update(
  ctx: *mut oxi_hmac_sha1_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha224_update(
  ctx: *mut oxi_hmac_sha224_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha256_update(
  ctx: *mut oxi_hmac_sha256_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha384_update(
  ctx: *mut oxi_hmac_sha384_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_update(
  ctx: *mut oxi_hmac_sha512_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_224_update(
  ctx: *mut oxi_hmac_sha512_224_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_256_update(
  ctx: *mut oxi_hmac_sha512_256_t,
  implementation: oxi_implementation_t,
  data: *const u8,
  datalen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.update(implementation, slice::from_raw_parts(data, datalen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha1_finish(
  ctx: *mut oxi_hmac_sha1_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha224_finish(
  ctx: *mut oxi_hmac_sha224_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha256_finish(
  ctx: *mut oxi_hmac_sha256_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha384_finish(
  ctx: *mut oxi_hmac_sha384_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_finish(
  ctx: *mut oxi_hmac_sha512_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_224_finish(
  ctx: *mut oxi_hmac_sha512_224_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_256_finish(
  ctx: *mut oxi_hmac_sha512_256_t,
  implementation: oxi_implementation_t,
  out: *mut u8,
  outlen: usize,
)
{
  let ctx = &mut *ctx;
  ctx.finish_into(implementation, slice::from_raw_parts_mut(out, outlen));
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha1_finish_sliced(
  ctx: *mut oxi_hmac_sha1_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha224_finish_sliced(
  ctx: *mut oxi_hmac_sha224_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha256_finish_sliced(
  ctx: *mut oxi_hmac_sha256_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha384_finish_sliced(
  ctx: *mut oxi_hmac_sha384_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_finish_sliced(
  ctx: *mut oxi_hmac_sha512_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_224_finish_sliced(
  ctx: *mut oxi_hmac_sha512_224_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_256_finish_sliced(
  ctx: *mut oxi_hmac_sha512_256_t,
  implementation: oxi_implementation_t,
) -> *const u8
{
  let ctx = &mut *ctx;
  ctx.finish_sliced(implementation).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha1_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha1::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha224_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha224::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha256_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha256::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha384_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha384::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha512::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_224_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha512_224::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}

#[no_mangle]
pub unsafe extern "C" fn oxi_hmac_sha512_256_oneshot(
  implementation: oxi_implementation_t,
  key: *const u8,
  keylen: usize,
  data: *const u8,
  datalen: usize,
  out: *mut u8,
  outlen: usize,
)
{
  HmacSha512_256::oneshot_into(
    implementation,
    slice::from_raw_parts(key, keylen),
    slice::from_raw_parts(data, datalen),
    slice::from_raw_parts_mut(out, outlen),
  );
}
