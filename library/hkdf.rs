//! HMAC based key derivation function.
//!
//! HKDF follows the "extract-then-expand" paradigm, where the KDF logically consists of two
//! modules. The first stage takes the input keying material and "extracts" from it a fixed-length
//! pseudorandom key `K`. The second stage "expands" the key `K` into several additional
//! pseudorandom keys (the output of KDF).
//!
//! # HKDF-Extract
//!
//! A pseudorandom key can be generated using HMAC. Because this step is trivial, it is not
//! included as a seperate function.
//!
//! ```
//! use oxicrypt::hmac::HmacSha256;
//!
//! let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
//! let ikm = [11; 22];
//! let prk = HmacSha256::oneshot(&salt, &ikm);
//! ```

use core::fmt::Debug;
use core::fmt::Display;
use core::mem::MaybeUninit;

use crate::hmac::Hmac;
use crate::sha;
use crate::Control;
use crate::Implementation;

/// HKDF-Expand.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "c", repr(C))]
pub struct Hkdf<D, const M: u64, const O: usize, const B: usize>
where
  D: Debug + Clone + Copy,
{
  hmac: Hmac<D, M, O, B>,
}

/// HKDF-SHA-1
pub type HkdfSha1 = Hkdf<sha::Sha1, 0x5ba_1, 20, 64>;
/// HKDF-SHA-224
pub type HkdfSha224 = Hkdf<sha::Sha224, 0x5ba_224, 28, 64>;
/// HKDF-SHA-256
pub type HkdfSha256 = Hkdf<sha::Sha256, 0x5ba_256, 32, 64>;
/// HKDF-SHA-384
pub type HkdfSha384 = Hkdf<sha::Sha384, 0x5ba_384, 48, 128>;
/// HKDF-SHA-512
pub type HkdfSha512 = Hkdf<sha::Sha512, 0x5ba_512, 64, 128>;
/// HKDF-SHA-512/224
pub type HkdfSha512_224 = Hkdf<sha::Sha512_224, 0x5ba_512_224, 28, 128>;
/// HKDF-SHA-512/256
pub type HkdfSha512_256 = Hkdf<sha::Sha512_256, 0x5ba_512_256, 32, 128>;

impl<D, const M: u64, const O: usize, const B: usize> Hkdf<D, M, O, B>
where
  D: Debug + Clone + Copy,
{
  pub fn with_prk(prk: &[u8]) -> Result<Self, LenError>
  {
    Self::with_prk_impl(Control::get_global_implementation(), prk)
  }

  pub fn with_prk_impl(implementation: Implementation, prk: &[u8]) -> Result<Self, LenError>
  {
    if prk.len() < O {
      return Err(LenError::Prk {
        at_least: O,
        got: prk.len(),
      });
    }
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut().set_prk_unchecked_impl(implementation, prk) };
    Ok(unsafe { ctx.assume_init() })
  }

  pub unsafe fn with_prk_unchecked(prk: &[u8]) -> Self
  {
    Self::with_prk_unchecked_impl(Control::get_global_implementation(), prk)
  }

  pub unsafe fn with_prk_unchecked_impl(implementation: Implementation, prk: &[u8]) -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    ctx.assume_init_mut().set_prk_unchecked_impl(implementation, prk);
    ctx.assume_init()
  }

  pub fn set_prk(&mut self, prk: &[u8]) -> Result<(), LenError>
  {
    self.set_prk_impl(Control::get_global_implementation(), prk)
  }

  pub fn set_prk_impl(&mut self, implementation: Implementation, prk: &[u8]) -> Result<(), LenError>
  {
    if prk.len() < O {
      return Err(LenError::Prk {
        at_least: O,
        got: prk.len(),
      });
    }
    unsafe { self.set_prk_unchecked_impl(implementation, prk) };
    Ok(())
  }

  pub unsafe fn set_prk_unchecked(&mut self, prk: &[u8])
  {
    self.set_prk_unchecked_impl(Control::get_global_implementation(), prk);
  }

  pub unsafe fn set_prk_unchecked_impl(&mut self, implementation: Implementation, prk: &[u8])
  {
    self.hmac.set_key_impl(implementation, prk);
  }

  pub fn expand(&self, info: &[&[u8]], okm: &mut [u8]) -> Result<(), LenError>
  {
    self.expand_impl(Control::get_global_implementation(), info, okm)
  }

  pub fn expand_impl(&self, implementation: Implementation, info: &[&[u8]], okm: &mut [u8]) -> Result<(), LenError>
  {
    if okm.len() > 255 * O {
      return Err(LenError::Okm {
        at_most: 255 * O,
        got: okm.len(),
      });
    }
    unsafe { self.expand_unchecked_impl(implementation, info, okm) };
    Ok(())
  }

  pub unsafe fn expand_unchecked(&self, info: &[&[u8]], okm: &mut [u8])
  {
    self.expand_unchecked_impl(Control::get_global_implementation(), info, okm);
  }

  pub unsafe fn expand_unchecked_impl(&self, implementation: Implementation, info: &[&[u8]], okm: &mut [u8])
  {
    let mut t: &[u8] = b"";
    let mut i = 0x00;
    let mut hmac: Hmac<D, M, O, B>;
    for chunk in okm.chunks_mut(O) {
      i += 1;
      hmac = self.hmac;
      hmac.update_impl(implementation, t);
      info.iter().for_each(|i| hmac.update_impl(implementation, i));
      hmac.update_impl(implementation, &[i]);
      hmac.finish_into_impl(implementation, chunk);
      t = chunk;
    }
  }
}

/// A structure representing an error for when the length of an input is not in an expected range.
#[derive(Clone, Copy, Debug)]
pub enum LenError
{
  Prk
  {
    at_least: usize, got: usize
  },
  Okm
  {
    at_most: usize, got: usize
  },
}

impl LenError
{
  pub const fn got(&self) -> usize
  {
    match self {
      | LenError::Prk { got, .. } => *got,
      | LenError::Okm { got, .. } => *got,
    }
  }
}

impl Display for LenError
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
  {
    match self {
      | LenError::Prk { at_least, got } => write!(
        f,
        "Length of `prk` is expected to be at least {}, but got {} instead",
        at_least, got
      ),
      | LenError::Okm { at_most, got } => write!(
        f,
        "Length of `okm` is expected to be at most {}, but got {} instead",
        at_most, got
      ),
    }
  }
}

#[cfg(any(feature = "std", doc))]
#[doc(cfg(feature = "std"))]
impl std::error::Error for LenError {}
