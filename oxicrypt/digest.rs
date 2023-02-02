//! Traits for working with digest algorithms.

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::cmp;
use core::mem::MaybeUninit;

#[cfg(not(any(feature = "alloc", doc)))]
pub trait Digest = DigestMeta + Reset + Update + Finish + FinishInternal + FinishToSlice;
#[cfg(any(feature = "alloc", doc))]
pub trait Digest = DigestMeta + Reset + Update + Finish + FinishBoxed + FinishInternal + FinishToSlice;

/// Information about the digest algorithm.
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

/// Auxilary trait for implementing the `Update` trait and the `Finish` traits. Most hashing
/// algorithms follow a similar pattern. This trait allows for us to automize the implementation.
pub(crate) trait DigestInternal
{
  /// The number of bytes required for the length counter.
  const LENGTH_COUNTER_W: usize;

  /// Compress the block into state. This is usually an unsafe operation under the hood. The caller
  /// must check that the block is full before processing.
  unsafe fn compress(&mut self);
  /// Get a mutable reference to the inner block.
  fn block(&mut self) -> &mut [u8];
  /// Get the index that the block is at.
  fn get_index(&self) -> usize;
  /// Set the index that the block is at.
  fn set_index(&mut self, index: usize);
  /// Increase the block count by 1.
  fn increase_block_count(&mut self);
  /// Get the block count.
  fn get_block_count(&self) -> usize;
  /// Write the bits counter to the block.
  fn write_bits(&mut self, bits: usize);
  /// Reorder the bytes in the state according to the endian.
  fn finish_state(&mut self);
  /// Get the untruncated state as bytes.
  fn state_as_bytes(&self) -> &[u8];
}

impl<T> Update for T
where
  T: DigestInternal + DigestMeta,
{
  fn update(&mut self, mut data: &[u8])
  {
    // Loop until all the data is processed.
    while !data.is_empty() {
      let index = self.get_index();
      let emptyspace = T::BLOCK_LEN - index;
      // If there is enough space in the block, then we can just copy `data` into `self.block`.
      if emptyspace >= data.len() {
        let newindex = index + data.len();
        self.block()[index .. newindex].copy_from_slice(data);
        self.set_index(newindex);
        // All of the data is read at this point. We need to set the length of `data` to 0 so we can exit
        // out of the loop.
        data = &data[0 .. 0];
      } else {
        self.block()[index .. T::BLOCK_LEN].copy_from_slice(&data[0 .. emptyspace]);
        // We filled `self.block` completely.
        self.set_index(T::BLOCK_LEN);
        data = &data[emptyspace ..];
      }

      if self.get_index() == T::BLOCK_LEN {
        // SAFETY: We know the inner block is full since we have checked for it.
        unsafe { self.compress() };
        self.set_index(0);
        self.increase_block_count();
      }
    }
  }
}

impl<T> FinishInternal for T
where
  T: DigestInternal + DigestMeta,
{
  fn finish_internal(&mut self) -> &[u8]
  {
    let index = self.get_index();
    // `len` represents the total number of bytes that have been processed by the algorithm. Later, we
    // will multiply it by 8 to get the number of bits which will be included at the end of the last
    // block.
    let len = self.get_block_count() * T::BLOCK_LEN + index;
    // We need to pad `self.block` with a "1" bit followed by "0" bits according to the specifications
    // of the algorithm. 0x80 byte represents 0b10000000. We can append this byte without checking if
    // the there is enough space, because a call to update would have reset the block if there weren't
    // enough space for at least one byte.
    self.block()[index] = 0x80;
    self.set_index(index + 1);

    // If there is not enough space to write the length counter, fill the remaining space in the block
    // with zeros and compress it.
    let index = self.get_index();
    if index > T::BLOCK_LEN - T::LENGTH_COUNTER_W {
      self.block()[index ..].fill(0);
      unsafe { self.compress() };
      self.set_index(0);
    }

    // Write the bits counter.
    let index = self.get_index();
    self.block()[index .. T::BLOCK_LEN - T::LENGTH_COUNTER_W].fill(0);
    let bits = len * 8;
    self.write_bits(bits);
    unsafe { self.compress() };

    self.finish_state();
    &self.state_as_bytes()[..T::DIGEST_LEN]
  }
}
