//! MD5 Algorithm
//!
//! # Examples
//!
//! Small example that demonstrates the usage of an MD5 function.
//!
//! ```rust
//! # use oxicrypt::digest::*;
//! # use oxicrypt::md5::*;
//! let mut ctx = Md5::default();
//!
//! ctx.update(b"Hello, ");
//! ctx.update(b"world");
//!
//! let digest = ctx.finish();
//! println!(
//!   "MD5 digest of \"Hello, world\" is {}.",
//!   hex::encode(&digest)
//! );
//! ````

use core::mem;
use core::mem::MaybeUninit;
use core::slice;

use oxicrypt_core::md5_generic_md5_compress;

use crate::digest::DigestMeta;
use crate::digest::FinishInternal;
use crate::digest::Reset;
use crate::digest::Update;
use crate::merkle_damgard;

const BLOCK_SIZE: usize = 64;
const DIGEST_SIZE: usize = 16;
const BIT_COUNT_LEN: usize = mem::size_of::<Counter>();
type Counter = u64;

#[derive(Debug, Clone, Copy)]
pub struct Md5
{
  h: [u32; 4],
  block: [u8; BLOCK_SIZE],
  index: usize,
  block_count: usize,
}

impl Md5
{
  #[inline(always)]
  pub const fn new() -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.reset();
    unsafe { ctx.assume_init() }
  }

  #[inline(always)]
  unsafe fn compress(h: *mut u32, block: *const u8)
  {
    md5_generic_md5_compress(h, block);
  }
}

impl DigestMeta for Md5
{
  const BLOCK_LEN: usize = BLOCK_SIZE;
  const DIGEST_LEN: usize = DIGEST_SIZE;
}

impl const Default for Md5
{
  #[inline(always)]
  fn default() -> Self
  {
    Self::new()
  }
}

impl const Reset for Md5
{
  #[inline(always)]
  fn reset(&mut self)
  {
    self.h = MD5_INITIAL_H;
    self.index = 0;
    self.block_count = 0;
  }
}

impl Update for Md5
{
  fn update(&mut self, data: &[u8])
  {
    let h_ptr = self.h.as_mut_ptr();
    let block_ptr = self.block.as_ptr();
    merkle_damgard::update::<Self, _>(
      data,
      &mut self.block,
      &mut self.index,
      &mut self.block_count,
      || unsafe { Self::compress(h_ptr, block_ptr) },
    );
  }
}

impl FinishInternal for Md5
{
  fn finish_internal(&mut self) -> &[u8]
  {
    // pointers to state and block
    let h_ptr = self.h.as_mut_ptr();
    let block_ptr = self.block.as_mut_ptr();

    // total number of bits processed
    let len = (self.block_count * Self::BLOCK_LEN + self.index) * 8;

    // pad with the bit pattern 1 0*
    merkle_damgard::pad::<Self, _>(&mut self.block, &mut self.index, BIT_COUNT_LEN, || unsafe {
      Self::compress(h_ptr, block_ptr)
    });

    // write the bit counter
    self.block[Self::BLOCK_LEN - BIT_COUNT_LEN ..].copy_from_slice(&Counter::to_le_bytes(len as _));

    // compress the final block
    unsafe { Self::compress(h_ptr, block_ptr) };

    // check endiannes
    self.h.iter_mut().for_each(|h0| *h0 = h0.to_le());
    unsafe { slice::from_raw_parts(h_ptr.cast(), Self::DIGEST_LEN) }
  }
}

/// Initial state of the MD5 algorithm.
#[rustfmt::skip]
pub const MD5_INITIAL_H: [u32; 4] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476
];
