//! # [Merkle–Damgård] construction
//!
//! There are many ways a cryptographic hash function may be constructed.
//! Merkle–Damgård construction uses a compression function in order to compress
//! each block into the appropriate state. A finalization step is then followed
//! and the final block is padded. Some of the most popular hashing algorithms
//! suchs as the SHA-2 family of functions use this construction.
//!
//! [Merkle–Damgård]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use core::intrinsics;
use core::marker::PhantomData;
use core::mem;
use core::mem::MaybeUninit;
use core::slice;

use num_traits::NumCast;
use num_traits::PrimInt;
use oxicrypt_core::*;

use crate::digest::DigestMeta;
use crate::digest::FinishInternal;
use crate::digest::Output;
use crate::digest::Reset;
use crate::digest::Update;
use crate::num::Be;
use crate::num::ByteOrder;
use crate::num::Endian;
use crate::num::Le;

/// Compression function used by Merkle–Damgård.
pub trait Compress<Int>
where
    Int: PrimInt,
{
    fn compress(h: *mut Int, b: *const u8);
}

/// Initialization vector used by the algorithm.
///
/// This is a `#[const_trait]`, so any implementation should use `impl const`.
#[const_trait]
pub trait InitializationVector<Int, const LEN: usize>
where
    Int: PrimInt,
{
    /// Initialization vector.
    fn initial() -> [Int; LEN];
}

/// Generic Merkle–Damgård construction.
#[derive(Debug, Clone, Copy)]
pub struct MerkleDamgard<
    State,
    Length,
    IV,
    Compress,
    Endian,
    const STATE_LEN: usize,
    const BLOCK_LEN: usize,
> where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    pub state: [State; STATE_LEN],
    pub block: [u8; BLOCK_LEN],
    pub index: usize,
    pub count: usize,
    _length:   PhantomData<Length>,
    _iv:       PhantomData<IV>,
    _compress: PhantomData<Compress>,
    _endian:   PhantomData<Endian>,
}

impl<State, Length, IV, Compress, Endian, const STATE_LEN: usize, const BLOCK_LEN: usize>
    MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    #[inline(always)]
    pub const fn new() -> Self
    {
        Self {
            state:     IV::initial(),
            block:     unsafe { MaybeUninit::uninit().assume_init() },
            index:     0,
            count:     0,
            _length:   PhantomData,
            _iv:       PhantomData,
            _compress: PhantomData,
            _endian:   PhantomData,
        }
    }

    #[inline(always)]
    pub fn compress(&mut self) { Compress::compress(self.state.as_mut_ptr(), self.block.as_ptr()); }

    /// Update the inner block and compress the state when the block is full
    /// according to the specifications of the Merkle–Damgård construction.
    pub fn update(&mut self, mut data: &[u8])
    {
        // Loop until all the data is processed.
        while !data.is_empty() {
            let emptyspace = BLOCK_LEN - self.index;
            // If there is enough space in the block, then we can just copy `data` into
            // `block`.
            if emptyspace >= data.len() {
                let newindex = self.index + data.len();
                self.block[self.index..newindex].copy_from_slice(data);
                self.index = newindex;
                // All of the data is read at this point. We need to set the length of `data` to
                // 0 so we can exit out of the loop.
                data = &data[0..0];
            } else {
                self.block[self.index..BLOCK_LEN].copy_from_slice(&data[0..emptyspace]);
                // We filled `self.block` completely.
                self.index = BLOCK_LEN;
                data = &data[emptyspace..];
            }

            if self.index == BLOCK_LEN {
                self.compress();
                self.index = 0;
                self.count += 1;
            }
        }
    }

    pub fn finish(&mut self)
    {
        // total number of bits processed
        let len = (self.count * BLOCK_LEN + self.index) * 8;

        // We need to pad `self.block` with a "1" bit followed by "0" bits according to
        // the specifications of the algorithm. 0x80 byte represents 0b10000000. We
        // can append this byte without checking if there is enough space, because a
        // call to update would have reset the block if there weren't enough space
        // for at least one byte.
        self.block[self.index] = 0x80;
        self.index += 1;

        // If there is not enough space to write the length counter, fill the remaining
        // space in the block with zeros and compress it.
        if self.index > BLOCK_LEN - mem::size_of::<Length>() {
            self.block[self.index..].fill(0);
            self.compress();
            self.index = 0;
        }

        self.block[self.index..BLOCK_LEN - mem::size_of::<Length>()].fill(0);

        // write the bit counter
        let len = match Endian::endian() {
            | ByteOrder::Little => <Length as NumCast>::from(len).unwrap().to_le(),
            | ByteOrder::Big => <Length as NumCast>::from(len).unwrap().to_be(),
        };
        unsafe {
            intrinsics::copy_nonoverlapping(
                &len as *const Length as *const u8,
                self.block
                    .as_mut_ptr()
                    .add(BLOCK_LEN - mem::size_of::<Length>()),
                mem::size_of::<Length>(),
            )
        };

        // compress the final block
        self.compress();

        // check endiannes
        self.state.iter_mut().for_each(|h0| {
            *h0 = match Endian::endian() {
                | ByteOrder::Little => h0.to_le(),
                | ByteOrder::Big => h0.to_be(),
            };
        });
    }
}

impl<State, Length, IV, Compress, Endian, const STATE_LEN: usize, const BLOCK_LEN: usize> const
    DigestMeta for MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    const BLOCK_LEN: usize = BLOCK_LEN;
    const DIGEST_LEN: usize = mem::size_of::<State>() * STATE_LEN;
}

impl<State, Length, IV, Compress, Endian, const STATE_LEN: usize, const BLOCK_LEN: usize> const
    Default for MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    fn default() -> Self { Self::new() }
}

impl<State, Length, IV, Compress, Endian, const STATE_LEN: usize, const BLOCK_LEN: usize> const
    Reset for MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    fn reset(&mut self)
    {
        self.state = IV::initial();
        self.index = 0;
        self.count = 0;
    }
}

impl<State, Length, IV, Compress, Endian, const STATE_LEN: usize, const BLOCK_LEN: usize> Update
    for MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    fn update(&mut self, data: &[u8]) { self.update(data); }
}

impl<State, Length, IV, Compress, Endian, const STATE_LEN: usize, const BLOCK_LEN: usize>
    FinishInternal for MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
where
    State: PrimInt,
    [State; STATE_LEN]:,
    Length: PrimInt,
    IV: ~const InitializationVector<State, STATE_LEN>,
    Compress: self::Compress<State>,
    Endian: ~const self::Endian,
{
    fn finish_internal(&mut self) -> &[u8]
    {
        self.finish();
        unsafe { slice::from_raw_parts(self.state.as_ptr().cast(), Self::DIGEST_LEN) }
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressSha1();
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressSha256();
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressSha512();
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressMd5();

impl Compress<u32> for CompressSha1
{
    fn compress(h: *mut u32, b: *const u8) { unsafe { sha_generic_sha1_compress(h, b) }; }
}

impl Compress<u32> for CompressSha256
{
    fn compress(h: *mut u32, b: *const u8) { unsafe { sha_generic_sha256_compress(h, b) }; }
}

impl Compress<u64> for CompressSha512
{
    fn compress(h: *mut u64, b: *const u8) { unsafe { sha_generic_sha512_compress(h, b) }; }
}

impl Compress<u32> for CompressMd5
{
    fn compress(h: *mut u32, b: *const u8) { unsafe { md5_generic_md5_compress(h, b) }; }
}

macro_rules! impl_iv {
    (const $iv_t:ident: [$int:ident; $len:expr] = $iv:ident) => {
        #[doc(hidden)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $iv_t();

        impl const InitializationVector<$int, $len> for $iv_t
        {
            fn initial() -> [$int; $len] { $iv }
        }
    };
}

impl_iv!(const IvSha1: [u32; 5] = SHA_INITIAL_H1);
impl_iv!(const IvSha224: [u32; 8] = SHA_INITIAL_H224);
impl_iv!(const IvSha256: [u32; 8] = SHA_INITIAL_H256);
impl_iv!(const IvSha384: [u64; 8] = SHA_INITIAL_H384);
impl_iv!(const IvSha512: [u64; 8] = SHA_INITIAL_H512);
impl_iv!(const IvSha512_224: [u64; 8] = SHA_INITIAL_H512_224);
impl_iv!(const IvSha512_256: [u64; 8] = SHA_INITIAL_H512_256);
impl_iv!(const IvMd5: [u32; 4] = MD5_INITIAL_H);

// MerkleDamgard<State, Length, IV, Compress, Endian, STATE_LEN, BLOCK_LEN>
pub type Sha1 = MerkleDamgard<u32, u64, IvSha1, CompressSha1, Be, 5, 64>;
pub type Sha224 = Output<MerkleDamgard<u32, u64, IvSha224, CompressSha256, Be, 8, 64>, 28>;
pub type Sha256 = MerkleDamgard<u32, u64, IvSha256, CompressSha256, Be, 8, 64>;
pub type Sha384 = Output<MerkleDamgard<u64, u128, IvSha384, CompressSha512, Be, 8, 128>, 48>;
pub type Sha512 = MerkleDamgard<u64, u128, IvSha512, CompressSha512, Be, 8, 128>;
pub type Sha512_224 =
    Output<MerkleDamgard<u64, u128, IvSha512_224, CompressSha512, Be, 8, 128>, 28>;
pub type Sha512_256 =
    Output<MerkleDamgard<u64, u128, IvSha512_256, CompressSha512, Be, 8, 128>, 32>;
pub type Md5 = MerkleDamgard<u32, u64, IvMd5, CompressMd5, Le, 4, 64>;

// Initial state for the SHA-1 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H1: [u32; 5] = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0,
];

/// Initial state for the SHA-224 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H224: [u32; 8] = [
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4,
];

/// Initial state for the SHA-256 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H256: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

/// Initial state for the SHA-384 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// Initial state for the SHA-512 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Initial state for the SHA-512/224 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H512_224: [u64; 8] = [
    0x8c3d37c819544da2,
    0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf,
    0x0f6d2b697bd44da8,
    0x77e36f7304c48942,
    0x3f9d85a86a1d36c8,
    0x1112e6ad91d692a1,
];

/// Initial state for the SHA-512/256 algorithm.
#[rustfmt::skip]
const SHA_INITIAL_H512_256: [u64; 8] = [
    0x22312194fc2bf72c,
    0x9f555fa3c84c64c2,
    0x2393b86b6f53b151,
    0x963877195940eabd,
    0x96283ee2a88effe3,
    0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa,
    0x0eb72ddc81c52ca2,
];

/// Initial state of the MD5 algorithm.
#[rustfmt::skip]
pub const MD5_INITIAL_H: [u32; 4] = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
];
