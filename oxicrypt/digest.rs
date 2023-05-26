//! Traits for working with digest algorithms.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::cmp;
use core::mem::MaybeUninit;

use crate::traits::New;

#[cfg(not(any(feature = "alloc", doc)))]
pub trait Digest = DigestMeta
    + Reset
    + Update
    + Finish
    + FinishInternal
    + FinishToSlice
    + Oneshot
    + OneshotToSlice;
#[cfg(any(feature = "alloc", doc))]
pub trait Digest = DigestMeta
    + Reset
    + Update
    + Finish
    + FinishBoxed
    + FinishInternal
    + FinishToSlice
    + Oneshot
    + OneshotBoxed
    + OneshotToSlice;

/// Information about the digest algorithm.
#[const_trait]
pub trait DigestMeta
{
    /// Digest length used by the algorithm.
    const DIGEST_LEN: usize;

    /// Block length used by the algorithm.
    const BLOCK_LEN: usize;
}

/// Trait for resetting the context to its original state.
#[const_trait]
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
    /// Calling this function will change the internal state, so any attempt to
    /// call [`update`](`Update::update`) or any other finish function will
    /// result in undefined behaviour. If you would like to keep updating
    /// the existing data, you may want to copy the object before using this
    /// function.
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
    /// Calling this function will change the internal state, so any attempt to
    /// call [`update`](`Update::update`) or any other finish function will
    /// result in undefined behaviour. If you would like to keep updating
    /// the existing data, you may want to copy the object before using this
    /// function.
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
        let mut digest_buffer: Box<[u8]> =
            unsafe { Box::new_uninit_slice(digest.len()).assume_init() };
        digest_buffer.copy_from_slice(digest);
        digest_buffer
    }
}

/// Trait for writing the digest value to a buffer.
pub trait FinishToSlice
{
    /// Calculate the digest and write it to the given buffer.
    ///
    /// Provided buffer may have a length smaller than the digest length, in
    /// which case only the first *N* bytes are written where *N* is the
    /// length of the buffer.
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
        buf[0..n].copy_from_slice(&digest[0..n]);
    }
}

/// Trait for getting the digest value which is stored in the context itself.
pub trait FinishInternal
{
    /// Calculate the digest and return a reference to it.
    ///
    /// Returned value references the context itself and will always have a
    /// length that is equal to the digest length used by the algorithm.
    fn finish_internal(&mut self) -> &[u8];
}

pub trait Oneshot
where
    Self: DigestMeta,
{
    fn oneshot(data: &[u8]) -> [u8; Self::DIGEST_LEN];
}

#[cfg(any(feature = "alloc", doc))]
pub trait OneshotBoxed
{
    fn oneshot_boxed(data: &[u8]) -> Box<[u8]>;
}

pub trait OneshotToSlice
{
    fn oneshot_to_slice(data: &[u8], buf: &mut [u8]);
}

impl<T> Oneshot for T
where
    T: New + Update + Finish,
{
    fn oneshot(data: &[u8]) -> [u8; Self::DIGEST_LEN]
    {
        let mut ctx = T::new();
        ctx.update(data);
        ctx.finish()
    }
}

#[cfg(any(feature = "alloc", doc))]
impl<T> OneshotBoxed for T
where
    T: New + Update + FinishBoxed,
{
    fn oneshot_boxed(data: &[u8]) -> Box<[u8]>
    {
        let mut ctx = T::new();
        ctx.update(data);
        ctx.finish_boxed()
    }
}

impl<T> OneshotToSlice for T
where
    T: New + Update + FinishToSlice,
{
    fn oneshot_to_slice(data: &[u8], buf: &mut [u8])
    {
        let mut ctx = T::new();
        ctx.update(data);
        ctx.finish_to_slice(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output<T, const DIGEST_LEN: usize>
where
    T: Digest,
{
    inner: T,
}

impl<T, const DIGEST_LEN: usize> Output<T, DIGEST_LEN>
where
    T: Digest + ~const New,
{
    pub const fn new() -> Self { Self { inner: T::new() } }
}

impl<T, const DIGEST_LEN: usize> const DigestMeta for Output<T, DIGEST_LEN>
where
    T: Digest,
{
    const BLOCK_LEN: usize = T::BLOCK_LEN;
    const DIGEST_LEN: usize = DIGEST_LEN;
}

impl<T, const DIGEST_LEN: usize> const New for Output<T, DIGEST_LEN>
where
    T: Digest + ~const New,
{
    fn new() -> Self { Self::new() }
}

impl<T, const DIGEST_LEN: usize> const Reset for Output<T, DIGEST_LEN>
where
    T: Digest + ~const Reset,
{
    fn reset(&mut self) { self.inner.reset(); }
}

impl<T, const DIGEST_LEN: usize> Update for Output<T, DIGEST_LEN>
where
    T: Digest,
{
    fn update(&mut self, data: &[u8]) { self.inner.update(data); }
}

impl<T, const DIGEST_LEN: usize> FinishInternal for Output<T, DIGEST_LEN>
where
    T: Digest,
{
    fn finish_internal(&mut self) -> &[u8] { &self.inner.finish_internal()[0..DIGEST_LEN] }
}
