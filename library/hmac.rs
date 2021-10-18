//! HMAC.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::fmt::Debug;
use core::mem::MaybeUninit;

use crate::digest::Digest;

/// HMAC context.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Hmac<D>
where
  D: Digest + Default + Clone + Copy,
  [u8; D::BLOCK_LEN]: Sized,
{
  digest: D,
  key: [u8; D::BLOCK_LEN],
  x5c: bool,
}

impl<D> core::hash::Hasher for Hmac<D>
where
  D: Digest + Default + Clone + Copy,
  [u8; D::DIGEST_LEN]: Sized,
  [u8; D::BLOCK_LEN]: Sized,
{
  fn finish(&self) -> u64
  {
    let mut ctx: Self = *self;
    let mut digest: MaybeUninit<[u8; 8]> = MaybeUninit::uninit();
    // FIXME: What if the digest length is less than 8 bytes long.
    unsafe { digest.assume_init_mut() }.copy_from_slice(&ctx.finish_internal()[0 .. 8]);
    u64::from_be_bytes(unsafe { digest.assume_init() })
  }

  fn write(&mut self, bytes: &[u8])
  {
    self.update(bytes);
  }
}

#[cfg(any(feature = "std", doc))]
#[doc(cfg(feature = "std"))]
impl<D> std::io::Write for Hmac<D>
where
  D: Digest + Default + Clone + Copy,
  [u8; D::DIGEST_LEN]: Sized,
  [u8; D::BLOCK_LEN]: Sized,
{
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>
  {
    self.update(buf);
    Ok(buf.len())
  }

  fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>
  {
    self.update(buf);
    Ok(())
  }

  fn flush(&mut self) -> std::io::Result<()>
  {
    Ok(())
  }
}

impl<D> Hmac<D>
where
  D: Digest + Default + Clone + Copy,
  [u8; D::DIGEST_LEN]: Sized,
  [u8; D::BLOCK_LEN]: Sized,
{
  pub fn with_key(key: &[u8]) -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.set_key(key);
    unsafe { ctx.assume_init() }
  }

  pub fn set_key(&mut self, key: &[u8])
  {
    self.digest.reset();

    self.key = [0; D::BLOCK_LEN];
    if key.len() > D::BLOCK_LEN {
      self.digest.update(key);
      self.digest.finish_to_slice(&mut self.key);
      self.digest.reset();
    } else {
      self.key[0 .. key.len()].copy_from_slice(key);
    }

    self.xor_key(0x36);
    self.x5c = false;

    self.digest.update(&self.key);
  }

  #[inline(always)]
  fn xor_key(&mut self, bits: u8)
  {
    for i in 0 .. D::BLOCK_LEN {
      self.key[i] ^= bits;
    }
  }

  pub fn reset_impl(&mut self)
  {
    if self.x5c {
      self.xor_key(0x36 ^ 0x5c);
      self.x5c = false;
    }

    self.digest.reset();
    self.digest.update(&self.key);
  }

  pub fn update(&mut self, data: &[u8])
  {
    self.digest.update(data);
  }

  pub fn finish(&mut self) -> [u8; D::DIGEST_LEN]
  {
    let mut output: MaybeUninit<[u8; D::DIGEST_LEN]> = MaybeUninit::uninit();
    unsafe { output.assume_init_mut() }.copy_from_slice(self.finish_internal());
    unsafe { output.assume_init() }
  }

  #[cfg(any(feature = "alloc", doc))]
  pub fn finish_boxed(&mut self) -> Box<[u8]>
  {
    let mut output: Box<[u8]> = unsafe { Box::new_uninit_slice(D::DIGEST_LEN).assume_init() };
    output.copy_from_slice(self.finish_internal());
    output
  }

  pub fn finish_to_slice(&mut self, buf: &mut [u8])
  {
    let n = core::cmp::min(D::DIGEST_LEN, buf.len());
    buf[0 .. n].copy_from_slice(&self.finish_internal()[0 .. n]);
  }

  pub fn finish_internal(&mut self) -> &[u8]
  {
    let digest = self.digest.finish();
    self.digest.reset();

    self.xor_key(0x36 ^ 0x5c);
    self.x5c = true;

    self.digest.update(&self.key);
    self.digest.update(&digest);

    self.digest.finish_internal()
  }
}
