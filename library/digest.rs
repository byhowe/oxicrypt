//! Traits for working with digest algorithms.

use alloc::boxed::Box;
use core::cmp;
use core::mem::MaybeUninit;

use crate::sha;
use crate::sha::Sha1;
use crate::sha::Sha224;
use crate::sha::Sha256;
use crate::sha::Sha384;
use crate::sha::Sha512;
use crate::sha::Sha512_224;
use crate::sha::Sha512_256;

/// Information about the digest algorithm.
pub trait DigestMeta
{
  /// Digest length used by the algorithm.
  const DIGEST_LEN: usize;

  /// Block length used by the algorithm.
  const BLOCK_LEN: usize;
}

/// Trait for accessing digest length of an algorithm.
pub trait DigestLen
{
  fn digest_len(&self) -> usize;
}

/// Trait for accessing inner block length of an algorithm.
pub trait BlockLen
{
  fn block_len(&self) -> usize;
}

impl<T> const DigestLen for T
where
  T: DigestMeta,
{
  fn digest_len(&self) -> usize
  {
    Self::DIGEST_LEN
  }
}

impl<T> const BlockLen for T
where
  T: DigestMeta,
{
  fn block_len(&self) -> usize
  {
    Self::BLOCK_LEN
  }
}

/// Trait for resetting the context to its original state.
pub trait Reset
{
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
pub trait Finish
where
  Self: DigestMeta,
{
  /// Calculate the digest and return it.
  ///
  /// Calling this function will change the internal state, so any attempt to call
  /// [`update`](`Update::update`) or any other finish function will result in undefined behaviour.
  /// If you would like to keep updating the existing data, you may want to copy the object before
  /// using this function.
  fn finish(&mut self) -> [u8; Self::DIGEST_LEN];
}

impl<T> Finish for T
where
  T: DigestMeta + FinishToSlice,
{
  fn finish(&mut self) -> [u8; Self::DIGEST_LEN]
  {
    let mut digest: MaybeUninit<[u8; Self::DIGEST_LEN]> = MaybeUninit::uninit();
    self.finish_to_slice(unsafe { digest.assume_init_mut() });
    unsafe { digest.assume_init() }
  }
}

/// Trait for getting the digest value in a [`Box`].
pub trait FinishBoxed
{
  /// Calculate the digest and return it in a [`Box`].
  ///
  /// Calling this function will change the internal state, so any attempt to call
  /// [`update`](`Update::update`) or any other finish function will result in undefined behaviour.
  /// If you would like to keep updating the existing data, you may want to copy the object before
  /// using this function.
  fn finish_boxed(&mut self) -> Box<[u8]>;
}

impl<T> FinishBoxed for T
where
  T: FinishInternal,
{
  fn finish_boxed(&mut self) -> Box<[u8]>
  {
    let digest = self.finish_internal();
    let mut digest_buffer: Box<[u8]> = unsafe { Box::new_uninit_slice(digest.len()).assume_init() };
    digest_buffer.copy_from_slice(digest);
    digest_buffer
  }
}

/// Trait for writing the digest value to a buffer.
pub trait FinishToSlice
{
  /// Calculate the digest and write it to the given buffer.
  ///
  /// Provided buffer may have a length smaller than the digest length, in which case only the first
  /// *N* bytes are written where *N* is the length of the buffer.
  fn finish_to_slice(&mut self, buf: &mut [u8]);
}

impl<T> FinishToSlice for T
where
  T: FinishInternal,
{
  fn finish_to_slice(&mut self, buf: &mut [u8])
  {
    let digest = self.finish_internal();
    let n = cmp::min(buf.len(), digest.len());
    buf[0 .. n].copy_from_slice(&digest[0 .. n]);
  }
}

/// Trait for getting the digest value which is stored in the context itself.
pub trait FinishInternal
{
  /// Calculate the digest and return a reference to it.
  ///
  /// Returned value references the context itself and will always have a length that is equal to
  /// the digest length used by the algorithm.
  fn finish_internal(&mut self) -> &[u8];
}

/// Marker trait for SHA objects.
pub trait Sha
{
}

/// Available digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgo
{
  Sha1 = 0,
  Sha224 = 1,
  Sha256 = 2,
  Sha384 = 3,
  Sha512 = 4,
  Sha512_224 = 5,
  Sha512_256 = 6,
}

pub trait DynDigest
where
  Self: DigestLen + BlockLen + Reset + Update + FinishBoxed + FinishInternal + FinishToSlice,
{
}

impl<T> DynDigest for T where T: DigestLen + BlockLen + Reset + Update + FinishBoxed + FinishInternal + FinishToSlice {}

pub fn generic(algo: DigestAlgo) -> Box<dyn DynDigest>
{
  match algo {
    | DigestAlgo::Sha1 => box Sha1::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha224 => box Sha224::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha256 => box Sha256::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha384 => box Sha384::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512 => box Sha512::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512_224 => box Sha512_224::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512_256 => box Sha512_256::<{ sha::Implementation::Generic }>::default(),
  }
}
