#![allow(clippy::missing_safety_doc)]

use core::slice;

use oxicrypt::hazmat::sha;
use oxicrypt::sha::Sha1;
use oxicrypt::sha::Sha224;
use oxicrypt::sha::Sha256;
use oxicrypt::sha::Sha384;
use oxicrypt::sha::Sha512;
use oxicrypt::sha::Sha512_224;
use oxicrypt::sha::Sha512_256;

use crate::oxi_implementation_t;

// Raw SHA functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_compress_generic(state: *mut u32, block: *const u8)
{
  sha::generic::sha1_compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_compress_generic(state: *mut u32, block: *const u8)
{
  sha::generic::sha256_compress(state, block);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_compress_generic(state: *mut u64, block: *const u8)
{
  sha::generic::sha512_compress(state, block);
}

// SHA engines.

#[allow(non_camel_case_types)]
pub type oxi_sha_engine1_t = sha::Engine1;
#[allow(non_camel_case_types)]
pub type oxi_sha_engine256_t = sha::Engine256;
#[allow(non_camel_case_types)]
pub type oxi_sha_engine512_t = sha::Engine512;

// SHA contexts.

#[allow(non_camel_case_types)]
type oxi_sha1_t = Sha1;
#[allow(non_camel_case_types)]
type oxi_sha224_t = Sha224;
#[allow(non_camel_case_types)]
type oxi_sha256_t = Sha256;
#[allow(non_camel_case_types)]
type oxi_sha384_t = Sha384;
#[allow(non_camel_case_types)]
type oxi_sha512_t = Sha512;
#[allow(non_camel_case_types)]
type oxi_sha512_224_t = Sha512_224;
#[allow(non_camel_case_types)]
type oxi_sha512_256_t = Sha512_256;

// SHA functions.

macro_rules! impl_sha {
  (
    type $sha:ident;
    fn reset = $reset:ident;
    fn update = $update:ident;
    fn update_impl = $update_impl:ident;
    fn finish_sliced = $finish_sliced:ident;
    fn finish_sliced_impl = $finish_sliced_impl:ident;
    fn finish_into = $finish_into:ident;
    fn finish_into_impl = $finish_into_impl:ident;
  ) => {
    #[no_mangle]
    pub unsafe extern "C" fn $reset(ctx: *mut $sha)
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.reset();
    }

    #[no_mangle]
    pub unsafe extern "C" fn $update(ctx: *mut $sha, data: *const u8, datalen: usize)
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.update(slice::from_raw_parts(data, datalen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $update_impl(
      ctx: *mut $sha,
      implementation: oxi_implementation_t,
      data: *const u8,
      datalen: usize,
    )
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.update_impl(implementation, slice::from_raw_parts(data, datalen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_sliced(ctx: *mut $sha) -> *const u8
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.finish_sliced().as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_sliced_impl(ctx: *mut $sha, implementation: oxi_implementation_t) -> *const u8
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.finish_sliced_impl(implementation).as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_into(ctx: *mut $sha, out: *mut u8, outlen: usize)
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.finish_into(slice::from_raw_parts_mut(out, outlen));
    }

    #[no_mangle]
    pub unsafe extern "C" fn $finish_into_impl(
      ctx: *mut $sha,
      implementation: oxi_implementation_t,
      out: *mut u8,
      outlen: usize,
    )
    {
      let ctx: &mut $sha = &mut *ctx;
      ctx.finish_into_impl(implementation, slice::from_raw_parts_mut(out, outlen));
    }
  };
}

impl_sha! {
  type oxi_sha1_t;
  fn reset = oxi_sha1_reset;
  fn update = oxi_sha1_update;
  fn update_impl = oxi_sha1_update_impl;
  fn finish_sliced = oxi_sha1_finish_sliced;
  fn finish_sliced_impl = oxi_sha1_finish_sliced_impl;
  fn finish_into = oxi_sha1_finish_into;
  fn finish_into_impl = oxi_sha1_finish_into_impl;
}

impl_sha! {
  type oxi_sha224_t;
  fn reset = oxi_sha224_reset;
  fn update = oxi_sha224_update;
  fn update_impl = oxi_sha224_update_impl;
  fn finish_sliced = oxi_sha224_finish_sliced;
  fn finish_sliced_impl = oxi_sha224_finish_sliced_impl;
  fn finish_into = oxi_sha224_finish_into;
  fn finish_into_impl = oxi_sha224_finish_into_impl;
}

impl_sha! {
  type oxi_sha256_t;
  fn reset = oxi_sha256_reset;
  fn update = oxi_sha256_update;
  fn update_impl = oxi_sha256_update_impl;
  fn finish_sliced = oxi_sha256_finish_sliced;
  fn finish_sliced_impl = oxi_sha256_finish_sliced_impl;
  fn finish_into = oxi_sha256_finish_into;
  fn finish_into_impl = oxi_sha256_finish_into_impl;
}

impl_sha! {
  type oxi_sha384_t;
  fn reset = oxi_sha384_reset;
  fn update = oxi_sha384_update;
  fn update_impl = oxi_sha384_update_impl;
  fn finish_sliced = oxi_sha384_finish_sliced;
  fn finish_sliced_impl = oxi_sha384_finish_sliced_impl;
  fn finish_into = oxi_sha384_finish_into;
  fn finish_into_impl = oxi_sha384_finish_into_impl;
}

impl_sha! {
  type oxi_sha512_t;
  fn reset = oxi_sha512_reset;
  fn update = oxi_sha512_update;
  fn update_impl = oxi_sha512_update_impl;
  fn finish_sliced = oxi_sha512_finish_sliced;
  fn finish_sliced_impl = oxi_sha512_finish_sliced_impl;
  fn finish_into = oxi_sha512_finish_into;
  fn finish_into_impl = oxi_sha512_finish_into_impl;
}

impl_sha! {
  type oxi_sha512_224_t;
  fn reset = oxi_sha512_224_reset;
  fn update = oxi_sha512_224_update;
  fn update_impl = oxi_sha512_224_update_impl;
  fn finish_sliced = oxi_sha512_224_finish_sliced;
  fn finish_sliced_impl = oxi_sha512_224_finish_sliced_impl;
  fn finish_into = oxi_sha512_224_finish_into;
  fn finish_into_impl = oxi_sha512_224_finish_into_impl;
}

impl_sha! {
  type oxi_sha512_256_t;
  fn reset = oxi_sha512_256_reset;
  fn update = oxi_sha512_256_update;
  fn update_impl = oxi_sha512_256_update_impl;
  fn finish_sliced = oxi_sha512_256_finish_sliced;
  fn finish_sliced_impl = oxi_sha512_256_finish_sliced_impl;
  fn finish_into = oxi_sha512_256_finish_into;
  fn finish_into_impl = oxi_sha512_256_finish_into_impl;
}
