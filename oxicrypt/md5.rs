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

use crate::digest::DigestInternal;
use crate::digest::DigestMeta;
use crate::digest::Reset;
use crate::digest::Update;
use crate::merkle_damgard;

const BLOCK_SIZE: usize = 64;
const DIGEST_SIZE: usize = 16;
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
      || unsafe { md5_generic_md5_compress(h_ptr, block_ptr) },
    );
  }
}

impl DigestInternal for Md5
{
  const LENGTH_COUNTER_W: usize = mem::size_of::<Counter>();

  unsafe fn compress(&mut self)
  {
    md5_generic_md5_compress(self.h.as_mut_ptr(), self.block.as_ptr());
  }

  fn block(&mut self) -> &mut [u8]
  {
    &mut self.block
  }

  fn get_index(&self) -> usize
  {
    self.index
  }

  fn set_index(&mut self, index: usize)
  {
    self.index = index;
  }

  fn increase_block_count(&mut self)
  {
    self.block_count += 1;
  }

  fn get_block_count(&self) -> usize
  {
    self.block_count
  }

  fn write_bits(&mut self, bits: usize)
  {
    self.block[Self::BLOCK_LEN - Self::LENGTH_COUNTER_W ..].copy_from_slice(&Counter::to_le_bytes(bits as _));
  }

  fn finish_state(&mut self)
  {
    self.h.iter_mut().for_each(|h0| *h0 = h0.to_le());
  }

  fn state_as_bytes(&self) -> &[u8]
  {
    let data = self.h.as_ptr().cast::<u8>();
    unsafe { slice::from_raw_parts(data, mem::size_of_val(&self.h)) }
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
