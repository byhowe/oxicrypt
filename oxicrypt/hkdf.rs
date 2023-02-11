//! HMAC based key derivation function.
//!
//! HKDF follows the "extract-then-expand" paradigm, where the KDF logically
//! consists of two modules. The first stage takes the input keying material and
//! "extracts" from it a fixed-length pseudorandom key `K`. The second stage
//! "expands" the key `K` into several additional pseudorandom keys (the output
//! of KDF).
//!
//! # HKDF-Extract
//!
//! A pseudorandom key can be generated using HMAC. Because this step is
//! trivial, it is not included as a seperate function.
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

use crate::digest::Digest;
use crate::hmac::Hmac;
use crate::merkle_damgard;

/// HKDF-Expand.
#[derive(Debug, Clone, Copy)]
pub struct Hkdf<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    hmac: Hmac<D>,
}

/// HKDF-MD5
pub type HkdfMd5 = Hkdf<merkle_damgard::Md5>;
/// HKDF-SHA-1
pub type HkdfSha1 = Hkdf<merkle_damgard::Sha1>;
/// HKDF-SHA-224
pub type HkdfSha224 = Hkdf<merkle_damgard::Sha224>;
/// HKDF-SHA-256
pub type HkdfSha256 = Hkdf<merkle_damgard::Sha256>;
/// HKDF-SHA-384
pub type HkdfSha384 = Hkdf<merkle_damgard::Sha384>;
/// HKDF-SHA-512
pub type HkdfSha512 = Hkdf<merkle_damgard::Sha512>;
/// HKDF-SHA-512/224
pub type HkdfSha512_224 = Hkdf<merkle_damgard::Sha512_224>;
/// HKDF-SHA-512/256
pub type HkdfSha512_256 = Hkdf<merkle_damgard::Sha512_256>;

impl<D> Hkdf<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    pub fn with_prk(prk: &[u8]) -> Result<Self, LenError>
    {
        if prk.len() < D::DIGEST_LEN {
            return Err(LenError::Prk {
                at_least: D::DIGEST_LEN,
                got:      prk.len(),
            });
        }
        let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe {
            ctx.assume_init_mut().set_prk_unchecked(prk);
        }
        Ok(unsafe { ctx.assume_init() })
    }

    pub unsafe fn with_prk_unchecked(prk: &[u8]) -> Self
    {
        let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
        ctx.assume_init_mut().set_prk_unchecked(prk);
        ctx.assume_init()
    }

    pub fn set_prk(&mut self, prk: &[u8]) -> Result<(), LenError>
    {
        if prk.len() < D::DIGEST_LEN {
            return Err(LenError::Prk {
                at_least: D::DIGEST_LEN,
                got:      prk.len(),
            });
        }
        unsafe {
            self.set_prk_unchecked(prk);
        }
        Ok(())
    }

    pub unsafe fn set_prk_unchecked(&mut self, prk: &[u8]) { self.hmac.set_key(prk); }

    pub fn expand(&self, info: &[&[u8]], okm: &mut [u8]) -> Result<(), LenError>
    {
        if okm.len() > 255 * D::DIGEST_LEN {
            return Err(LenError::Okm {
                at_most: 255 * D::DIGEST_LEN,
                got:     okm.len(),
            });
        }
        unsafe { self.expand_unchecked(info, okm) };
        Ok(())
    }

    pub unsafe fn expand_unchecked(&self, info: &[&[u8]], okm: &mut [u8])
    {
        let mut t: &[u8] = b"";
        let mut i = 0x00;
        let mut hmac: Hmac<D>;
        for chunk in okm.chunks_mut(D::DIGEST_LEN) {
            i += 1;
            hmac = self.hmac;
            hmac.update(t);
            info.iter().for_each(|i| hmac.update(i));
            hmac.update(&[i]);
            hmac.finish_to_slice(chunk);
            t = chunk;
        }
    }
}

/// A structure representing an error for when the length of an input is not in
/// an expected range.
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
