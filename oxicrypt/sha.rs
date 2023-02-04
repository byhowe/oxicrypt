//! SHA Algorithms
//!
//! # Examples
//!
//! Small example that demonstrates the usage of a SHA function.
//!
//! ```rust
//! # use oxicrypt::digest::*;
//! # use oxicrypt::sha::*;
//! let mut ctx = Sha256::default();
//!
//! ctx.update(b"Hello, ");
//! ctx.update(b"world");
//!
//! let digest = ctx.finish();
//! println!(
//!     "SHA-256 digest of \"Hello, world\" is {}.",
//!     hex::encode(&digest)
//! );
//! ````

use core::mem;
use core::mem::MaybeUninit;
use core::slice;

use oxicrypt_core::sha_generic_sha1_compress;
use oxicrypt_core::sha_generic_sha256_compress;
use oxicrypt_core::sha_generic_sha512_compress;

use crate::digest::DigestMeta;
use crate::digest::FinishInternal;
use crate::digest::Reset;
use crate::digest::Update;
use crate::merkle_damgard;

macro_rules! impl_sha {
    (
        struct $alg_name:ident;
        fn compress = $compress:ident;
        type BitCounter = $counter_int:ident;
        const STATE: [$state_int:ident; $statew:expr] = $initial_state:expr;
        const BLOCK_LEN = $block_len:expr;
        const DIGEST_LEN = $digest_len:expr;
    ) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $alg_name
        {
            h:           [$state_int; $statew],
            block:       [u8; $block_len],
            index:       usize,
            block_count: usize,
        }

        impl $alg_name
        {
            const BIT_COUNT_LEN: usize = mem::size_of::<$counter_int>();

            #[inline(always)]
            pub const fn new() -> Self
            {
                let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
                unsafe { ctx.assume_init_mut() }.reset();
                unsafe { ctx.assume_init() }
            }

            #[inline(always)]
            unsafe fn compress(h: *mut $state_int, block: *const u8) { $compress(h, block); }
        }

        impl DigestMeta for $alg_name
        {
            const BLOCK_LEN: usize = $block_len;
            const DIGEST_LEN: usize = $digest_len;
        }

        impl const Default for $alg_name
        {
            #[inline(always)]
            fn default() -> Self { Self::new() }
        }

        impl const Reset for $alg_name
        {
            #[inline(always)]
            fn reset(&mut self)
            {
                self.h = $initial_state;
                self.index = 0;
                self.block_count = 0;
            }
        }

        impl Update for $alg_name
        {
            fn update(&mut self, data: &[u8])
            {
                let h_ptr = self.h.as_mut_ptr();
                let block_ptr = self.block.as_ptr();
                merkle_damgard::update::<Self, _>(
                    data,
                    &mut self.block,
                    &mut self.index,
                    &mut self.block_count,
                    || unsafe { Self::compress(h_ptr, block_ptr) },
                );
            }
        }

        impl FinishInternal for $alg_name
        {
            fn finish_internal(&mut self) -> &[u8]
            {
                // pointers to state and block
                let h_ptr = self.h.as_mut_ptr();
                let block_ptr = self.block.as_mut_ptr();

                // total number of bits processed
                let len = (self.block_count * Self::BLOCK_LEN + self.index) * 8;

                // pad with the bit pattern 1 0*
                merkle_damgard::pad::<Self, _>(
                    &mut self.block,
                    &mut self.index,
                    Self::BIT_COUNT_LEN,
                    || unsafe { Self::compress(h_ptr, block_ptr) },
                );

                // write the bit counter
                self.block[Self::BLOCK_LEN - Self::BIT_COUNT_LEN..]
                    .copy_from_slice(&$counter_int::to_be_bytes(len as _));

                // compress the final block
                unsafe { Self::compress(h_ptr, block_ptr) };

                // check endiannes
                self.h.iter_mut().for_each(|h0| *h0 = h0.to_be());
                unsafe { slice::from_raw_parts(h_ptr.cast(), Self::DIGEST_LEN) }
            }
        }

        impl core::hash::Hasher for $alg_name
        {
            fn finish(&self) -> u64
            {
                // The state is copied here, since we need a mutable reference but cant with the
                // borrow.
                let mut ctx: Self = *self;
                let mut digest: MaybeUninit<[u8; 8]> = MaybeUninit::uninit();
                // FIXME: What if the digest length is less than 8 bytes long.
                unsafe { digest.assume_init_mut() }.copy_from_slice(&ctx.finish_internal()[0..8]);
                u64::from_be_bytes(unsafe { digest.assume_init() })
            }

            fn write(&mut self, bytes: &[u8]) { self.update(bytes); }
        }

        #[cfg(any(feature = "std", doc))]
        #[doc(cfg(feature = "std"))]
        impl std::io::Write for $alg_name
        {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>
            {
                self.update(buf);
                Ok(buf.len())
            }

            fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>
            {
                self.update(buf);
                Ok(())
            }

            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
    };
}

impl_sha! {
    struct Sha1;
    fn compress = sha_generic_sha1_compress;
    type BitCounter = u64;
    const STATE: [u32; 5] = SHA_INITIAL_H1;
    const BLOCK_LEN = 64;
    const DIGEST_LEN = 20;
}

impl_sha! {
    struct Sha224;
    fn compress = sha_generic_sha256_compress;
    type BitCounter = u64;
    const STATE: [u32; 8] = SHA_INITIAL_H224;
    const BLOCK_LEN = 64;
    const DIGEST_LEN = 28;
}

impl_sha! {
    struct Sha256;
    fn compress = sha_generic_sha256_compress;
    type BitCounter = u64;
    const STATE: [u32; 8] = SHA_INITIAL_H256;
    const BLOCK_LEN = 64;
    const DIGEST_LEN = 32;
}

impl_sha! {
    struct Sha384;
    fn compress = sha_generic_sha512_compress;
    type BitCounter = u128;
    const STATE: [u64; 8] = SHA_INITIAL_H384;
    const BLOCK_LEN = 128;
    const DIGEST_LEN = 48;
}

impl_sha! {
    struct Sha512;
    fn compress = sha_generic_sha512_compress;
    type BitCounter = u128;
    const STATE: [u64; 8] = SHA_INITIAL_H512;
    const BLOCK_LEN = 128;
    const DIGEST_LEN = 64;
}

impl_sha! {
    struct Sha512_224;
    fn compress = sha_generic_sha512_compress;
    type BitCounter = u128;
    const STATE: [u64; 8] = SHA_INITIAL_H512_224;
    const BLOCK_LEN = 128;
    const DIGEST_LEN = 28;
}

impl_sha! {
    struct Sha512_256;
    fn compress = sha_generic_sha512_compress;
    type BitCounter = u128;
    const STATE: [u64; 8] = SHA_INITIAL_H512_256;
    const BLOCK_LEN = 128;
    const DIGEST_LEN = 32;
}

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
