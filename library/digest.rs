//! Traits for working with digest algorithms.

use core::fmt::Debug;
use core::mem::transmute;
use core::mem::MaybeUninit;

/// Common trait for digest objects.
pub trait Digest = DigestInformation + Reset + Update + Finish + Oneshot;

/// Information about the digest algorithm.
pub trait DigestInformation
{
  /// Digest length used by the algorithm.
  const DIGEST_LEN: usize;

  /// Block length used by the algorithm.
  const BLOCK_LEN: usize;
}

/// Trait for resetting the context to its original state.
pub trait Reset
where
  Self: Sized,
{
  /// Create a new context.
  fn new() -> Self
  {
    let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
    unsafe { ctx.assume_init_mut() }.reset();
    unsafe { ctx.assume_init() }
  }

  /// Reset the context to its original state.
  fn reset(&mut self);
}

/// Trait for feeding more data to the context.
pub trait Update
{
  /// Update the context.
  fn update(&mut self, data: &[u8]);
}

/// Trait for getting the digest value.
///
/// Calling any of these functions will change the internal state, so any attempt to call
/// [`update`](`Update::update`) or finish functions will result in an undefined behaviour. If you
/// would like to keep updating the existing data, you may want to copy the object before using this
/// trait.
pub trait Finish
where
  Self: DigestInformation,
{
  /// Calculate the digest and return it.
  fn finish(&mut self) -> [u8; Self::DIGEST_LEN]
  {
    let mut digest: MaybeUninit<[u8; Self::DIGEST_LEN]> = MaybeUninit::uninit();
    self.finish_into(unsafe { digest.assume_init_mut() });
    unsafe { digest.assume_init() }
  }

  // TODO: find a better name to describe this function.
  /// Calculate the digest and write it to the given buffer.
  ///
  /// Provided buffer may have a length smaller than the digest length, in which case only the first
  /// *N* bytes are written.
  fn finish_into(&mut self, buf: &mut [u8]);
}

/// Trait for quickly calculating the digest value of a data.
pub trait Oneshot
where
  Self: DigestInformation,
{
  fn oneshot(data: &[u8]) -> [u8; Self::DIGEST_LEN];

  fn oneshot_into(data: &[u8], buf: &mut [u8]);
}

impl<T> Oneshot for T
where
  T: Reset + Update + Finish,
{
  fn oneshot(data: &[u8]) -> [u8; Self::DIGEST_LEN]
  {
    let mut ctx = Self::new();
    ctx.update(data);
    ctx.finish()
  }

  fn oneshot_into(data: &[u8], buf: &mut [u8])
  {
    let mut ctx = Self::new();
    ctx.update(data);
    ctx.finish_into(buf);
  }
}
