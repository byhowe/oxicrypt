//! SHA family of hash functions.

use std::cmp;
use std::mem;
use std::mem::MaybeUninit;

use oxicrypt_core::sha::generic::sha1_compress_generic;
use oxicrypt_core::sha::generic::sha256_compress_generic;
use oxicrypt_core::sha::generic::sha512_compress_generic;
use oxicrypt_core::sha::H1;
use oxicrypt_core::sha::H224;
use oxicrypt_core::sha::H256;
use oxicrypt_core::sha::H384;
use oxicrypt_core::sha::H512;
use oxicrypt_core::sha::H512_224;
use oxicrypt_core::sha::H512_256;

macro_rules! impl_sha {
  (
    $algo_str:expr;
    struct $algo:ident;
    type Len = $lenty:ty;
    const INITIAL_H: [$uint:ty; $statelen:expr] = $H:ident;
    const BLOCK_LEN: usize = $blocklen:expr;
    const DIGEST_LEN: usize = $digestlen:expr;
    fn compress = $compressfn:ident;
  ) => {
    #[doc = concat!($algo_str, " algorithm.")]
    pub struct $algo
    {
      h: [$uint; $statelen],
      block: [u8; $blocklen],
      len: u64,
      blocklen: usize,
    }

    impl $algo
    {
      /// Creates a new instance of
      #[doc = $algo_str]
      /// on the stack.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new();")]
      /// ```
      pub const fn new() -> Self
      {
        Self {
          h: $H,
          block: [0; $blocklen],
          len: 0,
          blocklen: 0,
        }
      }

      /// Creates a new instance of
      #[doc = $algo_str]
      /// on the heap.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new_boxed();")]
      /// ```
      pub fn new_boxed() -> Box<Self>
      {
        let mut ctx: Box<MaybeUninit<Self>> = Box::new_uninit();
        unsafe { ctx.assume_init_mut() }.reset();
        unsafe { ctx.assume_init() }
      }

      /// Resets the context to its original state.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new();")]
      /// ctx.update(b"Hello World");
      /// // Digest value of 'Hello World'.
      /// let hello_world_digest = ctx.finish();
      ///
      /// ctx.reset();
      ///
      /// ctx.update(b"Hei Verden");
      /// // Digest value of 'Hei Verden'.
      /// let hei_verden_digest = ctx.finish();
      /// ```
      pub fn reset(&mut self)
      {
        self.h = $H;
        self.block = [0; $blocklen];
        self.len = 0;
        self.blocklen = 0;
      }

      /// Updates state with the given data.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new();")]
      /// ctx.update(b"Hello World");
      /// ```
      pub fn update(&mut self, mut data: &[u8])
      {
        while !data.is_empty() {
          let emptyspace = $blocklen - self.blocklen;
          if emptyspace >= data.len() {
            let newblocklen = self.blocklen + data.len();
            self.block[self.blocklen .. newblocklen].copy_from_slice(data);
            self.blocklen = newblocklen;
            data = &data[0 .. 0];
          } else {
            self.block[self.blocklen .. $blocklen].copy_from_slice(&data[0 .. emptyspace]);
            self.blocklen = $blocklen;
            data = &data[emptyspace ..];
          }
          if self.blocklen == $blocklen {
            unsafe { $compressfn(self.h.as_mut_ptr(), self.block.as_ptr()) };
            self.blocklen = 0;
            self.len += $blocklen;
          }
        }
      }

      /// Returns the digest of the data the context has been fed using [`update`](`Self::update`).
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new();")]
      /// ctx.update(b"Hello World");
      /// let digest = ctx.finish();
      /// ```
      pub fn finish(&mut self) -> [u8; $digestlen]
      {
        let mut output = [0; $digestlen];
        self.finish_into(&mut output);
        output
      }

      /// Returns the digest of the data the context has been fed using [`update`](`Self::update`).
      /// The data returned lives on the heap.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new();")]
      /// ctx.update(b"Hello World");
      /// let digest = ctx.finish_boxed();
      /// ```
      pub fn finish_boxed(&mut self) -> Box<[u8]>
      {
        let mut output = unsafe { Box::new_uninit_slice($digestlen).assume_init() };
        self.finish_into(&mut output);
        output
      }

      /// Writes the digest of the data the context has been fed using [`update`](`Self::update`)
      /// into `output`. Note that if the length of `output` is less than
      #[doc = stringify!($digestlen)]
      /// , digest gets truncated.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let mut ctx = ", stringify!($algo), "::new();")]
      /// ctx.update(b"Hello World");
      /// // Only the first 15 bytes of the digest will get written.
      /// let mut digest: Vec<u8> = vec![0; 15];
      /// let digest = ctx.finish_into(&mut digest);
      /// ```
      pub fn finish_into(&mut self, output: &mut [u8])
      {
        self.block[self.blocklen] = 0b10000000;
        self.len += self.blocklen as u64;
        self.blocklen += 1;

        if self.blocklen > ($blocklen - mem::size_of::<$lenty>()) {
          self.block[self.blocklen ..].fill(0);
          unsafe { $compressfn(self.h.as_mut_ptr(), self.block.as_ptr()) };
          self.blocklen = 0;
        }

        self.block[self.blocklen .. ($blocklen - 8)].fill(0);
        self.len *= 8;
        self.len = self.len.to_be();
        self.block[($blocklen - 8) .. $blocklen].copy_from_slice(&self.len.to_ne_bytes());
        unsafe { $compressfn(self.h.as_mut_ptr(), self.block.as_ptr()) };

        let mut cur_bytes: [u8; mem::size_of::<$uint>()] = [0; mem::size_of::<$uint>()];
        for i in 0 .. cmp::min(output.len(), $digestlen) {
          let cur_bytes_rem = i % mem::size_of::<$uint>();
          if cur_bytes_rem == 0 {
            cur_bytes = self.h[i / mem::size_of::<$uint>()].to_be_bytes();
          }
          output[i] = cur_bytes[cur_bytes_rem];
        }

        self.reset();
      }

      /// Returns the digest of `data` in one go.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let digest = ", stringify!($algo), "::oneshot(b\"Hello World\");")]
      /// ```
      pub fn oneshot(data: &[u8]) -> [u8; $digestlen]
      {
        let mut ctx = Self::new();
        ctx.update(data);
        ctx.finish()
      }

      /// Returns the digest of `data` in one go. The data returned lives on the heap.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      #[doc = concat!("let digest = ", stringify!($algo), "::oneshot_boxed(b\"Hello World\");")]
      /// ```
      pub fn oneshot_boxed(data: &[u8]) -> Box<[u8]>
      {
        let mut ctx = Self::new();
        ctx.update(data);
        ctx.finish_boxed()
      }

      /// Returns the digest of `data` in one go. Note that if the length of `output` is less than
      #[doc = stringify!($digestlen)]
      /// , digest gets truncated.
      ///
      /// # Examples
      ///
      /// ```
      #[doc = concat!("use oxicrypt::sha::", stringify!($algo), ";")]
      /// // Only the first 15 bytes of the digest will get written.
      /// let mut digest: Vec<u8> = vec![0; 15];
      #[doc = concat!("let digest = ", stringify!($algo), "::oneshot_into(b\"Hello World\", &mut digest);")]
      /// ```
      pub fn oneshot_into(data: &[u8], output: &mut [u8])
      {
        let mut ctx = Self::new();
        ctx.update(data);
        ctx.finish_into(output);
      }
    }
  };
}

impl_sha! {
    "SHA-1";
    struct Sha1;
    type Len = u64;
    const INITIAL_H: [u32; 5] = H1;
    const BLOCK_LEN: usize = 64;
    const DIGEST_LEN: usize = 20;
    fn compress = sha1_compress_generic;
}

impl_sha! {
    "SHA-224";
    struct Sha224;
    type Len = u64;
    const INITIAL_H: [u32; 8] = H224;
    const BLOCK_LEN: usize = 64;
    const DIGEST_LEN: usize = 28;
    fn compress = sha256_compress_generic;
}

impl_sha! {
    "SHA-256";
    struct Sha256;
    type Len = u64;
    const INITIAL_H: [u32; 8] = H256;
    const BLOCK_LEN: usize = 64;
    const DIGEST_LEN: usize = 32;
    fn compress = sha256_compress_generic;
}

impl_sha! {
    "SHA-384";
    struct Sha384;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H384;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 48;
    fn compress = sha512_compress_generic;
}

impl_sha! {
    "SHA-512";
    struct Sha512;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H512;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 64;
    fn compress = sha512_compress_generic;
}

impl_sha! {
    "SHA-512/224";
    struct Sha512_224;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H512_224;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 28;
    fn compress = sha512_compress_generic;
}

impl_sha! {
    "SHA-512/256";
    struct Sha512_256;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H512_256;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 32;
    fn compress = sha512_compress_generic;
}
