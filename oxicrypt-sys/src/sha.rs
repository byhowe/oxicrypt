use core::cmp;
use core::mem;

use oxicrypt_core::sha::generic::sha1_compress_generic;
use oxicrypt_core::sha::generic::sha256_compress_generic;
use oxicrypt_core::sha::generic::sha512_compress_generic;
use oxicrypt_core::sha::H1;
use oxicrypt_core::sha::H224;
use oxicrypt_core::sha::H256;
use oxicrypt_core::sha::H384;
use oxicrypt_core::sha::H512;
use oxicrypt_core::sha::H512_224;
use oxicrypt_core::sha::H512_256;

// Type definitions.

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_sha1_ctx_t
{
  h: [u32; 5],
  block: [u8; 64],
  len: u64,
  blocklen: usize,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_sha256_ctx_t
{
  h: [u32; 8],
  block: [u8; 64],
  len: u64,
  blocklen: usize,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct oxi_sha512_ctx_t
{
  h: [u64; 8],
  block: [u8; 128],
  len: u64,
  blocklen: usize,
}

pub type oxi_sha224_ctx_t = oxi_sha256_ctx_t;
pub type oxi_sha384_ctx_t = oxi_sha512_ctx_t;
pub type oxi_sha512_224_ctx_t = oxi_sha512_ctx_t;
pub type oxi_sha512_256_ctx_t = oxi_sha512_ctx_t;

impl oxi_sha1_ctx_t
{
  #[inline(always)]
  fn compress(&mut self)
  {
    unsafe { sha1_compress_generic(self.h.as_mut_ptr(), self.block.as_ptr()) };
  }
}

impl oxi_sha256_ctx_t
{
  #[inline(always)]
  fn compress(&mut self)
  {
    unsafe { sha256_compress_generic(self.h.as_mut_ptr(), self.block.as_ptr()) };
  }
}

impl oxi_sha512_ctx_t
{
  #[inline(always)]
  fn compress(&mut self)
  {
    unsafe { sha512_compress_generic(self.h.as_mut_ptr(), self.block.as_ptr()) };
  }
}

impl Default for oxi_sha1_ctx_t
{
  #[inline(always)]
  fn default() -> Self
  {
    Self {
      h: [0; 5],
      block: [0; 64],
      len: 0,
      blocklen: 0,
    }
  }
}

impl Default for oxi_sha256_ctx_t
{
  #[inline(always)]
  fn default() -> Self
  {
    Self {
      h: [0; 8],
      block: [0; 64],
      len: 0,
      blocklen: 0,
    }
  }
}

impl Default for oxi_sha512_ctx_t
{
  #[inline(always)]
  fn default() -> Self
  {
    Self {
      h: [0; 8],
      block: [0; 128],
      len: 0,
      blocklen: 0,
    }
  }
}

// Init functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_init(ctx: *mut oxi_sha1_ctx_t)
{
  let ctx: &mut oxi_sha1_ctx_t = &mut *ctx;
  ctx.h = H1;
  ctx.block = [0; 64];
  ctx.len = 0;
  ctx.blocklen = 0;
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_init(ctx: *mut oxi_sha224_ctx_t)
{
  let ctx: &mut oxi_sha224_ctx_t = &mut *ctx;
  ctx.h = H224;
  ctx.block = [0; 64];
  ctx.len = 0;
  ctx.blocklen = 0;
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_init(ctx: *mut oxi_sha256_ctx_t)
{
  let ctx: &mut oxi_sha256_ctx_t = &mut *ctx;
  ctx.h = H256;
  ctx.block = [0; 64];
  ctx.len = 0;
  ctx.blocklen = 0;
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_init(ctx: *mut oxi_sha384_ctx_t)
{
  let ctx: &mut oxi_sha384_ctx_t = &mut *ctx;
  ctx.h = H384;
  ctx.block = [0; 128];
  ctx.len = 0;
  ctx.blocklen = 0;
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_init(ctx: *mut oxi_sha512_ctx_t)
{
  let ctx: &mut oxi_sha512_ctx_t = &mut *ctx;
  ctx.h = H512;
  ctx.block = [0; 128];
  ctx.len = 0;
  ctx.blocklen = 0;
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_init(ctx: *mut oxi_sha512_224_ctx_t)
{
  let ctx: &mut oxi_sha512_224_ctx_t = &mut *ctx;
  ctx.h = H512_224;
  ctx.block = [0; 128];
  ctx.len = 0;
  ctx.blocklen = 0;
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_init(ctx: *mut oxi_sha512_256_ctx_t)
{
  let ctx: &mut oxi_sha512_256_ctx_t = &mut *ctx;
  ctx.h = H512_256;
  ctx.block = [0; 128];
  ctx.len = 0;
  ctx.blocklen = 0;
}

// Update functions.

macro_rules! sha_update {
  ($ctx:ident, $data:ident, $datalen:ident, $blocklen:expr) => {
    while $datalen != 0 {
      let emptyspace = $blocklen - $ctx.blocklen;
      if emptyspace >= $datalen {
        let newblocklen = $ctx.blocklen + $datalen;
        $ctx
          .block
          .as_mut_ptr()
          .add($ctx.blocklen)
          .copy_from_nonoverlapping($data, newblocklen - $ctx.blocklen);
        $ctx.blocklen = newblocklen;
        $datalen = 0;
      } else {
        $ctx
          .block
          .as_mut_ptr()
          .add($ctx.blocklen)
          .copy_from_nonoverlapping($data, $blocklen - $ctx.blocklen);
        $ctx.blocklen = 64;
        $data = $data.add(emptyspace);
        $datalen -= emptyspace;
      }
      if $ctx.blocklen == 64 {
        $ctx.compress();
        $ctx.blocklen = 0;
        $ctx.len += 64;
      }
    }
  };
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_update(ctx: *mut oxi_sha1_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha1_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 64);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_update(ctx: *mut oxi_sha224_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha224_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 64);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_update(ctx: *mut oxi_sha256_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha256_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 64);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_update(ctx: *mut oxi_sha384_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha384_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 128);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_update(ctx: *mut oxi_sha512_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha512_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 128);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_update(ctx: *mut oxi_sha512_224_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha512_224_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 128);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_update(ctx: *mut oxi_sha512_256_ctx_t, mut data: *const u8, mut datalen: usize)
{
  let ctx: &mut oxi_sha512_256_ctx_t = &mut *ctx;
  sha_update!(ctx, data, datalen, 128);
}

// Finish functions.

macro_rules! sha_finish {
  ($ctx:ident, $out:ident, $outlen:ident, $blocklen:expr, $digestlen:expr, $lenty:ty, $statewordty:ty) => {
    $ctx.block[$ctx.blocklen] = 0b10000000;
    $ctx.len += $ctx.blocklen as u64;
    $ctx.blocklen += 1;

    if $ctx.blocklen > ($blocklen - mem::size_of::<$lenty>()) {
      $ctx.block[$ctx.blocklen ..].fill(0);
      $ctx.compress();
      $ctx.blocklen = 0;
    }

    $ctx.block[$ctx.blocklen .. ($blocklen - 8)].fill(0);
    $ctx.len *= 8;
    $ctx.len = $ctx.len.to_be();
    $ctx.block[($blocklen - 8) .. $blocklen].copy_from_slice(&$ctx.len.to_ne_bytes());
    $ctx.compress();

    let mut cur_bytes = [0; mem::size_of::<$statewordty>()];
    for i in 0 .. cmp::min($outlen, $digestlen) {
      let cur_bytes_rem = i % mem::size_of::<$statewordty>();
      if cur_bytes_rem == 0 {
        cur_bytes = $ctx.h[i / mem::size_of::<$statewordty>()].to_be_bytes();
      }
      *$out.add(i) = cur_bytes[cur_bytes_rem];
    }
  };
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_finish(ctx: *mut oxi_sha1_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha1_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 64, 20, u64, u32);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_finish(ctx: *mut oxi_sha224_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha224_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 64, 28, u64, u32);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_finish(ctx: *mut oxi_sha256_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha256_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 64, 32, u64, u32);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_finish(ctx: *mut oxi_sha384_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha384_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 128, 48, u128, u64);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_finish(ctx: *mut oxi_sha512_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha512_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 128, 64, u128, u64);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_finish(ctx: *mut oxi_sha512_224_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha512_224_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 128, 28, u128, u64);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_finish(ctx: *mut oxi_sha512_256_ctx_t, out: *mut u8, outlen: usize)
{
  let ctx: &mut oxi_sha512_256_ctx_t = &mut *ctx;
  sha_finish!(ctx, out, outlen, 128, 32, u128, u64);
}

// Convenience functions.

#[no_mangle]
pub unsafe extern "C" fn oxi_sha1_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha1_ctx_t::default();
  oxi_sha1_init(&mut ctx);
  oxi_sha1_update(&mut ctx, data, datalen);
  oxi_sha1_finish(&mut ctx, out, outlen);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha224_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha256_ctx_t::default();
  oxi_sha224_init(&mut ctx);
  oxi_sha224_update(&mut ctx, data, datalen);
  oxi_sha224_finish(&mut ctx, out, outlen);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha256_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha256_ctx_t::default();
  oxi_sha256_init(&mut ctx);
  oxi_sha256_update(&mut ctx, data, datalen);
  oxi_sha256_finish(&mut ctx, out, outlen);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha384_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha512_ctx_t::default();
  oxi_sha384_init(&mut ctx);
  oxi_sha384_update(&mut ctx, data, datalen);
  oxi_sha384_finish(&mut ctx, out, outlen);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha512_ctx_t::default();
  oxi_sha512_init(&mut ctx);
  oxi_sha512_update(&mut ctx, data, datalen);
  oxi_sha512_finish(&mut ctx, out, outlen);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_224_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha512_ctx_t::default();
  oxi_sha512_224_init(&mut ctx);
  oxi_sha512_224_update(&mut ctx, data, datalen);
  oxi_sha512_224_finish(&mut ctx, out, outlen);
}

#[no_mangle]
pub unsafe extern "C" fn oxi_sha512_256_oneshot(data: *const u8, datalen: usize, out: *mut u8, outlen: usize)
{
  let mut ctx = oxi_sha512_ctx_t::default();
  oxi_sha512_256_init(&mut ctx);
  oxi_sha512_256_update(&mut ctx, data, datalen);
  oxi_sha512_256_finish(&mut ctx, out, outlen);
}
