//! HMAC.

use core::fmt::Debug;
use core::mem::MaybeUninit;

use crate::digest::Digest;
use crate::sha;
use crate::Control;
use crate::Implementation;

/// HMAC context.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Hmac<D, const M: u64, const O: usize, const B: usize>
where
  D: Debug + Clone + Copy,
{
  digest: Digest<D, M, O>,
  key: [u8; B],
  x5c: bool,
}

/// HMAC-SHA-1
pub type HmacSha1 = Hmac<sha::Sha1, 0x5ba_1, 20, 64>;
/// HMAC-SHA-224
pub type HmacSha224 = Hmac<sha::Sha224, 0x5ba_224, 28, 64>;
/// HMAC-SHA-256
pub type HmacSha256 = Hmac<sha::Sha256, 0x5ba_256, 32, 64>;
/// HMAC-SHA-384
pub type HmacSha384 = Hmac<sha::Sha384, 0x5ba_384, 48, 128>;
/// HMAC-SHA-512
pub type HmacSha512 = Hmac<sha::Sha512, 0x5ba_512, 64, 128>;
/// HMAC-SHA-512/224
pub type HmacSha512_224 = Hmac<sha::Sha512_224, 0x5ba_512_224, 28, 128>;
/// HMAC-SHA-512/256
pub type HmacSha512_256 = Hmac<sha::Sha512_256, 0x5ba_512_256, 32, 128>;

impl<D, const M: u64, const O: usize, const B: usize> Hmac<D, M, O, B>
where
  D: Debug + Clone + Copy,
{
  pub fn with_key(key: &[u8]) -> Self
  {
    Self::with_key_impl(Control::get_global_implementation(), key)
  }

  pub fn with_key_impl(implementation: Implementation, key: &[u8]) -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.set_key_impl(implementation, key);
    unsafe { ctx.assume_init() }
  }

  pub fn set_key(&mut self, key: &[u8])
  {
    self.set_key_impl(Control::get_global_implementation(), key);
  }

  pub fn set_key_impl(&mut self, implementation: Implementation, key: &[u8])
  {
    self.digest.reset();

    self.key = [0; B];
    if key.len() > B {
      self.digest.update_impl(implementation, key);
      self.digest.finish_into_impl(implementation, &mut self.key);
      self.digest.reset();
    } else {
      self.key[0 .. key.len()].copy_from_slice(key);
    }

    self.xor_key(0x36);
    self.x5c = false;

    self.digest.update_impl(implementation, &self.key);
  }

  #[inline(always)]
  fn xor_key(&mut self, bits: u8)
  {
    for i in 0 .. B {
      self.key[i] ^= bits;
    }
  }

  pub fn reset(&mut self)
  {
    self.reset_impl(Control::get_global_implementation());
  }

  pub fn reset_impl(&mut self, implementation: Implementation)
  {
    if self.x5c {
      self.xor_key(0x36 ^ 0x5c);
      self.x5c = false;
    }

    self.digest.reset();
    self.digest.update_impl(implementation, &self.key);
  }

  pub fn update(&mut self, data: &[u8])
  {
    self.update_impl(Control::get_global_implementation(), data)
  }

  pub fn update_impl(&mut self, implementation: Implementation, data: &[u8])
  {
    self.digest.update_impl(implementation, data);
  }

  pub fn finish_sliced<'context>(&'context mut self) -> &'context [u8]
  {
    self.finish_sliced_impl(Control::get_global_implementation())
  }

  pub fn finish_sliced_impl<'context>(&'context mut self, implementation: Implementation) -> &'context [u8]
  {
    let digest = self.digest.finish_impl(implementation);
    self.digest.reset();

    self.xor_key(0x36 ^ 0x5c);
    self.x5c = true;

    self.digest.update_impl(implementation, &self.key);
    self.digest.update_impl(implementation, &digest);

    self.digest.finish_sliced_impl(implementation)
  }

  pub fn finish(&mut self) -> [u8; O]
  {
    self.finish_impl(Control::get_global_implementation())
  }

  pub fn finish_impl(&mut self, implementation: Implementation) -> [u8; O]
  {
    let mut output: MaybeUninit<[u8; O]> = MaybeUninit::uninit();
    unsafe { output.assume_init_mut() }.copy_from_slice(self.finish_sliced_impl(implementation));
    unsafe { output.assume_init() }
  }

  pub fn finish_into(&mut self, output: &mut [u8])
  {
    self.finish_into_impl(Control::get_global_implementation(), output);
  }

  pub fn finish_into_impl(&mut self, implementation: Implementation, output: &mut [u8])
  {
    let n = core::cmp::min(O, output.len());
    output[0 .. n].copy_from_slice(&self.finish_sliced_impl(implementation)[0 .. n]);
  }
}
