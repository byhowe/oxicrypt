//! # [HMAC]
//!
//! HMACs are also referred to as keyed-hash message authentication code. The
//! implementation in this module is based on the pseudocode on the Wikipedia
//! page.
//!
//! [HMAC]: https://en.wikipedia.org/wiki/HMAC

#[cfg(any(feature = "alloc", doc))]
use alloc::boxed::Box;
use core::fmt::Debug;
use core::mem::MaybeUninit;

use crate::digest::Digest;
use crate::digest::DigestMeta;
use crate::digest::FinishInternal;
use crate::digest::Update;

/// Oneshot HMAC function.
pub fn hmac<D>(data: &[u8], key: &[u8]) -> [u8; D::DIGEST_LEN]
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    let mut ctx = Hmac::<D>::with_key(key);
    ctx.update(data);
    ctx.finish_();
    ctx.ctx.finish()
}

/// Oneshot HMAC function that puts the result in `buf`.
///
/// Same principles apply as [`FinishToSlice`](`crate::digest::FinishToSlice`).
pub fn hmac_to_slice<D>(data: &[u8], key: &[u8], buf: &mut [u8])
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    let mut ctx = Hmac::<D>::with_key(key);
    ctx.update(data);
    ctx.finish_to_slice(buf);
}

/// Oneshot HMAC function that returns a boxed array.
#[cfg(any(feature = "alloc", doc))]
#[doc(cfg(feature = "alloc"))]
pub fn hmac_boxed<D: Digest + Default>(data: &[u8], key: &[u8]) -> Box<[u8]>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    use crate::digest::FinishBoxed;

    let mut ctx = Hmac::<D>::with_key(key);
    ctx.update(data);
    ctx.finish_boxed()
}

/// HMAC-X context.
#[derive(Debug, Clone, Copy)]
pub struct Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    ikey: [u8; D::BLOCK_LEN],
    ctx:  D,
}

impl<D> DigestMeta for Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    const BLOCK_LEN: usize = D::BLOCK_LEN;
    const DIGEST_LEN: usize = D::DIGEST_LEN;
}

impl<D> Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    /// Create a new context using the key.
    pub fn with_key(key: &[u8]) -> Self
    {
        let mut ctx: MaybeUninit<Self> = MaybeUninit::uninit();
        unsafe { ctx.assume_init_mut() }.set_key(key);
        unsafe { ctx.assume_init() }
    }

    /// Set the key.
    ///
    /// This process will reset the inner state of the hash context as well as
    /// the key.
    pub fn set_key(&mut self, key: &[u8])
    {
        self.ikey = [0; D::BLOCK_LEN];
        self.ctx.reset();

        // key shortening
        if key.len() > D::BLOCK_LEN {
            self.ctx.update(key);
            self.ctx.finish_to_slice(&mut self.ikey[0..D::DIGEST_LEN]);
            self.ctx.reset();
        } else {
            self.ikey[0..key.len()].copy_from_slice(key);
        }

        // xor with 0x36 to get i_key_pad
        self.ikey.iter_mut().for_each(|b0| *b0 ^= 0x36);

        self.ctx.update(&self.ikey);
    }

    fn finish_(&mut self)
    {
        let i_digest = self.ctx.finish();
        self.ctx.reset();

        // xor with 0x36 ^ 0x5c. xoring with 0x36 again has the effect of getting the
        // original ikey and xoring with 0x5c is what we need in the next step.
        self.ikey.iter_mut().for_each(|b0| *b0 ^= 0x36 ^ 0x5c);
        self.ctx.update(&self.ikey);
        self.ctx.update(&i_digest);
    }
}

impl<D> FinishInternal for Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    /// Finish the HMAC calculation and return a reference to the inner state.
    fn finish_internal(&mut self) -> &[u8]
    {
        self.finish_();
        self.ctx.finish_internal()
    }
}

impl<D> Update for Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
{
    /// Update the inner state.
    fn update(&mut self, data: &[u8]) { self.ctx.update(data); }
}

impl<D> core::hash::Hasher for Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
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
impl<D> std::io::Write for Hmac<D>
where
    D: Digest + Copy,
    [u8; D::BLOCK_LEN]:,
    [u8; D::DIGEST_LEN]:,
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
