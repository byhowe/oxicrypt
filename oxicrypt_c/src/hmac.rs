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

// HMAC functions.

macro_rules! impl_hmac {
  (
    type $hmac:ident;
    fn set_key = $set_key:ident;
    fn set_key_impl = $set_key_impl:ident;
    fn reset = $reset:ident;
    fn reset_impl = $reset_impl:ident;
    fn update = $update:ident;
    fn update_impl = $update_impl:ident;
    fn finish_sliced = $finish_sliced:ident;
    fn finish_sliced_impl = $finish_sliced_impl:ident;
    fn finish = $finish:ident;
    fn finish_impl = $finish_impl:ident;
    fn oneshot = $oneshot:ident;
    fn oneshot_impl = $oneshot_impl:ident;
  ) => {
    #[no_mangle]
    pub unsafe extern "C" fn $set_key(ctx: *mut $hmac, key: *const u8, keylen: usize)
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.set_key(slice::from_raw_parts(key, keylen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $set_key_impl(
      ctx: *mut $hmac,
      implementation: oxi_implementation_t,
      key: *const u8,
      keylen: usize,
    )
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.set_key_impl(implementation, slice::from_raw_parts(key, keylen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $reset(ctx: *mut $hmac)
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.reset();
    }

    #[no_mangle]
    pub unsafe extern "C" fn $reset_impl(ctx: *mut $hmac, implementation: oxi_implementation_t)
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.reset_impl(implementation);
    }

    #[no_mangle]
    pub unsafe extern "C" fn $update(ctx: *mut $hmac, data: *const u8, datalen: usize)
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.update(slice::from_raw_parts(data, datalen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $update_impl(
      ctx: *mut $hmac,
      implementation: oxi_implementation_t,
      data: *const u8,
      datalen: usize,
    )
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.update_impl(implementation, slice::from_raw_parts(data, datalen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_sliced(ctx: *mut $hmac) -> *const u8
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.finish_sliced().as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_sliced_impl(ctx: *mut $hmac, implementation: oxi_implementation_t) -> *const u8
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.finish_sliced_impl(implementation).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish(ctx: *mut $hmac, out: *mut u8, outlen: usize)
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.finish_into(slice::from_raw_parts_mut(out, outlen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_impl(
      ctx: *mut $hmac,
      implementation: oxi_implementation_t,
      out: *mut u8,
      outlen: usize,
    )
    {
      let ctx: &mut $hmac = &mut *ctx;
      ctx.finish_into_impl(implementation, slice::from_raw_parts_mut(out, outlen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $oneshot(
      key: *const u8,
      keylen: usize,
      data: *const u8,
      datalen: usize,
      out: *mut u8,
      outlen: usize,
    )
    {
      $hmac::oneshot_into(
        slice::from_raw_parts(key, keylen),
        slice::from_raw_parts(data, datalen),
        slice::from_raw_parts_mut(out, outlen),
      );
    }

    #[no_mangle]
    pub unsafe extern "C" fn $oneshot_impl(
      implementation: oxi_implementation_t,
      key: *const u8,
      keylen: usize,
      data: *const u8,
      datalen: usize,
      out: *mut u8,
      outlen: usize,
    )
    {
      $hmac::oneshot_into_impl(
        implementation,
        slice::from_raw_parts(key, keylen),
        slice::from_raw_parts(data, datalen),
        slice::from_raw_parts_mut(out, outlen),
      );
    }
  };
}

impl_hmac! {
  type oxi_hmac_sha1_t;
  fn set_key = oxi_hmac_sha1_set_key;
  fn set_key_impl = oxi_hmac_sha1_set_key_impl;
  fn reset = oxi_hmac_sha1_reset;
  fn reset_impl = oxi_hmac_sha1_reset_impl;
  fn update = oxi_hmac_sha1_update;
  fn update_impl = oxi_hmac_sha1_update_impl;
  fn finish_sliced = oxi_hmac_sha1_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha1_finish_sliced_impl;
  fn finish = oxi_hmac_sha1_finish;
  fn finish_impl = oxi_hmac_sha1_finish_impl;
  fn oneshot = oxi_hmac_sha1_oneshot;
  fn oneshot_impl = oxi_hmac_sha1_oneshot_impl;
}

impl_hmac! {
  type oxi_hmac_sha224_t;
  fn set_key = oxi_hmac_sha224_set_key;
  fn set_key_impl = oxi_hmac_sha224_set_key_impl;
  fn reset = oxi_hmac_sha224_reset;
  fn reset_impl = oxi_hmac_sha224_reset_impl;
  fn update = oxi_hmac_sha224_update;
  fn update_impl = oxi_hmac_sha224_update_impl;
  fn finish_sliced = oxi_hmac_sha224_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha224_finish_sliced_impl;
  fn finish = oxi_hmac_sha224_finish;
  fn finish_impl = oxi_hmac_sha224_finish_impl;
  fn oneshot = oxi_hmac_sha224_oneshot;
  fn oneshot_impl = oxi_hmac_sha224_oneshot_impl;
}

impl_hmac! {
  type oxi_hmac_sha256_t;
  fn set_key = oxi_hmac_sha256_set_key;
  fn set_key_impl = oxi_hmac_sha256_set_key_impl;
  fn reset = oxi_hmac_sha256_reset;
  fn reset_impl = oxi_hmac_sha256_reset_impl;
  fn update = oxi_hmac_sha256_update;
  fn update_impl = oxi_hmac_sha256_update_impl;
  fn finish_sliced = oxi_hmac_sha256_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha256_finish_sliced_impl;
  fn finish = oxi_hmac_sha256_finish;
  fn finish_impl = oxi_hmac_sha256_finish_impl;
  fn oneshot = oxi_hmac_sha256_oneshot;
  fn oneshot_impl = oxi_hmac_sha256_oneshot_impl;
}

impl_hmac! {
  type oxi_hmac_sha384_t;
  fn set_key = oxi_hmac_sha384_set_key;
  fn set_key_impl = oxi_hmac_sha384_set_key_impl;
  fn reset = oxi_hmac_sha384_reset;
  fn reset_impl = oxi_hmac_sha384_reset_impl;
  fn update = oxi_hmac_sha384_update;
  fn update_impl = oxi_hmac_sha384_update_impl;
  fn finish_sliced = oxi_hmac_sha384_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha384_finish_sliced_impl;
  fn finish = oxi_hmac_sha384_finish;
  fn finish_impl = oxi_hmac_sha384_finish_impl;
  fn oneshot = oxi_hmac_sha384_oneshot;
  fn oneshot_impl = oxi_hmac_sha384_oneshot_impl;
}

impl_hmac! {
  type oxi_hmac_sha512_t;
  fn set_key = oxi_hmac_sha512_set_key;
  fn set_key_impl = oxi_hmac_sha512_set_key_impl;
  fn reset = oxi_hmac_sha512_reset;
  fn reset_impl = oxi_hmac_sha512_reset_impl;
  fn update = oxi_hmac_sha512_update;
  fn update_impl = oxi_hmac_sha512_update_impl;
  fn finish_sliced = oxi_hmac_sha512_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha512_finish_sliced_impl;
  fn finish = oxi_hmac_sha512_finish;
  fn finish_impl = oxi_hmac_sha512_finish_impl;
  fn oneshot = oxi_hmac_sha512_oneshot;
  fn oneshot_impl = oxi_hmac_sha512_oneshot_impl;
}

impl_hmac! {
  type oxi_hmac_sha512_224_t;
  fn set_key = oxi_hmac_sha512_224_set_key;
  fn set_key_impl = oxi_hmac_sha512_224_set_key_impl;
  fn reset = oxi_hmac_sha512_224_reset;
  fn reset_impl = oxi_hmac_sha512_224_reset_impl;
  fn update = oxi_hmac_sha512_224_update;
  fn update_impl = oxi_hmac_sha512_224_update_impl;
  fn finish_sliced = oxi_hmac_sha512_224_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha512_224_finish_sliced_impl;
  fn finish = oxi_hmac_sha512_224_finish;
  fn finish_impl = oxi_hmac_sha512_224_finish_impl;
  fn oneshot = oxi_hmac_sha512_224_oneshot;
  fn oneshot_impl = oxi_hmac_sha512_224_oneshot_impl;
}

impl_hmac! {
  type oxi_hmac_sha512_256_t;
  fn set_key = oxi_hmac_sha512_256_set_key;
  fn set_key_impl = oxi_hmac_sha512_256_set_key_impl;
  fn reset = oxi_hmac_sha512_256_reset;
  fn reset_impl = oxi_hmac_sha512_256_reset_impl;
  fn update = oxi_hmac_sha512_256_update;
  fn update_impl = oxi_hmac_sha512_256_update_impl;
  fn finish_sliced = oxi_hmac_sha512_256_finish_sliced;
  fn finish_sliced_impl = oxi_hmac_sha512_256_finish_sliced_impl;
  fn finish = oxi_hmac_sha512_256_finish;
  fn finish_impl = oxi_hmac_sha512_256_finish_impl;
  fn oneshot = oxi_hmac_sha512_256_oneshot;
  fn oneshot_impl = oxi_hmac_sha512_256_oneshot_impl;
}
