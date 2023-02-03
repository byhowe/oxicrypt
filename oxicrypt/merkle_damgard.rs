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

/// Pad the final block with "1" bit followed by "0" bits.
///
/// After this process, the block will have an empty space at the end worth `bit_count_len` bytes.
/// This space should be filled with the bit count information. The bit count information should be
/// calculated before the call to this `pad` functions since the function modifes the value of
/// `index`. The endiannes of the bit count also matters. SHA-1 and SHA-2 use big-endian while MD5
/// uses little endian. The process of length-padding is caleld Merkle–Damgård strengthening. After
/// this strengthening process, call the appropriate compress function once again and change the
/// endiannes of the state integers according to what the algorithm calls for.
pub fn pad<D: DigestMeta, C: Fn()>(block: &mut [u8], index: &mut usize, bit_count_len: usize, compress: C)
{
  // We need to pad `self.block` with a "1" bit followed by "0" bits according to the specifications
  // of the algorithm. 0x80 byte represents 0b10000000. We can append this byte without checking if
  // there is enough space, because a call to update would have reset the block if there weren't
  // enough space for at least one byte.
  block[*index] = 0x80;
  *index += 1;

  // If there is not enough space to write the length counter, fill the remaining space in the block
  // with zeros and compress it.
  if *index > D::BLOCK_LEN - bit_count_len {
    block[*index ..].fill(0);
    compress();
    *index = 0;
  }

  block[*index .. D::BLOCK_LEN - bit_count_len].fill(0);
}
