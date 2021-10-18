//! Traits for working with digest algorithms.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::cmp;
use core::mem::MaybeUninit;

#[cfg(any(feature = "alloc", doc))]
use crate::sha;

#[cfg(not(any(feature = "alloc", doc)))]
pub trait Digest = DigestMeta + DigestLen + BlockLen + Reset + Update + Finish + FinishInternal + FinishToSlice;
#[cfg(any(feature = "alloc", doc))]
pub trait Digest =
  DigestMeta + DigestLen + BlockLen + Reset + Update + Finish + FinishBoxed + FinishInternal + FinishToSlice;

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
#[cfg(any(feature = "alloc", doc))]
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

#[cfg(any(feature = "alloc", doc))]
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

#[cfg(any(feature = "alloc", doc))]
pub trait DynDigest
where
  Self: DigestLen + BlockLen + Reset + Update + FinishBoxed + FinishInternal + FinishToSlice,
{
}

#[cfg(any(feature = "alloc", doc))]
impl<T> DynDigest for T where T: DigestLen + BlockLen + Reset + Update + FinishBoxed + FinishInternal + FinishToSlice {}

/// Return a context that uses generic implementations of compression functions.
#[cfg(any(feature = "alloc", doc))]
pub fn generic(algo: DigestAlgo) -> Box<dyn DynDigest>
{
  match algo {
    | DigestAlgo::Sha1 => box sha::Sha1::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha224 => box sha::Sha224::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha256 => box sha::Sha256::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha384 => box sha::Sha384::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512 => box sha::Sha512::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512_224 => box sha::Sha512_224::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512_256 => box sha::Sha512_256::<{ sha::Implementation::Generic }>::default(),
  }
}

/// Return a context that uses cpu-optimized implementations of compression functions when
/// available.
#[cfg(any(feature = "alloc", doc))]
pub fn cpu_optimized(algo: DigestAlgo) -> Box<dyn DynDigest>
{
  match algo {
    | DigestAlgo::Sha1 => box sha::Sha1::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha224 => box sha::Sha224::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha256 => box sha::Sha256::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha384 => box sha::Sha384::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512 => box sha::Sha512::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512_224 => box sha::Sha512_224::<{ sha::Implementation::Generic }>::default(),
    | DigestAlgo::Sha512_256 => box sha::Sha512_256::<{ sha::Implementation::Generic }>::default(),
  }
}
