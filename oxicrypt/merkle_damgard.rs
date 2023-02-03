//! # [Merkle–Damgård] construction
//!
//! There are many ways a cryptographic hash function may be constructed. Merkle–Damgård
//! construction uses a compression function in order to compress each block into the appropriate
//! state. A finalization step is then followed and the final block is padded. Some of the most
//! popular hashing algorithms suchs as the SHA-2 family of functions use this construction.
//!
//! [Merkle–Damgård]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use crate::digest::DigestMeta;

/// Update the inner block and compress the state when the block is full according to the
/// specifications of the Merkle–Damgård construction.
#[inline(always)]
pub fn update<D: DigestMeta, C: Fn()>(
  mut data: &[u8],
  block: &mut [u8],
  index: &mut usize,
  block_count: &mut usize,
  compress: C,
)
{
  // Loop until all the data is processed.
  while !data.is_empty() {
    let emptyspace = D::BLOCK_LEN - *index;
    // If there is enough space in the block, then we can just copy `data` into `block`.
    if emptyspace >= data.len() {
      let newindex = *index + data.len();
      block[*index .. newindex].copy_from_slice(data);
      *index = newindex;
      // All of the data is read at this point. We need to set the length of `data` to 0 so we can exit
      // out of the loop.
      data = &data[0 .. 0];
    } else {
      block[*index .. D::BLOCK_LEN].copy_from_slice(&data[0 .. emptyspace]);
      // We filled `self.block` completely.
      *index = D::BLOCK_LEN;
      data = &data[emptyspace ..];
    }

    if *index == D::BLOCK_LEN {
      compress();
      *index = 0;
      *block_count += 1;
    }
  }
}
