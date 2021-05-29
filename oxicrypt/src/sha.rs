use std::mem::MaybeUninit;
use std::{cmp, mem};

use oxicrypt_core::sha::{sha1_compress_generic, sha256_compress_generic, sha512_compress_generic};

#[rustfmt::skip]
const H1: [u32; 5] = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
  0xc3d2e1f0,
];

#[rustfmt::skip]
const H224: [u32; 8] = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];

#[rustfmt::skip]
const H256: [u32; 8] = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

#[rustfmt::skip]
const H384: [u64; 8] = [
  0xcbbb9d5dc1059ed8,
  0x629a292a367cd507,
  0x9159015a3070dd17,
  0x152fecd8f70e5939,
  0x67332667ffc00b31,
  0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7,
  0x47b5481dbefa4fa4,
];

#[rustfmt::skip]
const H512: [u64; 8] = [
  0x6a09e667f3bcc908,
  0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1,
  0x510e527fade682d1,
  0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b,
  0x5be0cd19137e2179,
];

#[rustfmt::skip]
const H512_224: [u64; 8] = [
  0x8c3d37c819544da2,
  0x73e1996689dcd4d6,
  0x1dfab7ae32ff9c82,
  0x679dd514582f9fcf,
  0x0f6d2b697bd44da8,
  0x77e36f7304c48942,
  0x3f9d85a86a1d36c8,
  0x1112e6ad91d692a1,
];

#[rustfmt::skip]
const H512_256: [u64; 8] = [
  0x22312194fc2bf72c,
  0x9f555fa3c84c64c2,
  0x2393b86b6f53b151,
  0x963877195940eabd,
  0x96283ee2a88effe3,
  0xbe5e1e2553863992,
  0x2b0199fc2c85b8aa,
  0x0eb72ddc81c52ca2,
];

macro_rules! impl_sha {
  (
    struct $algo:ident;
    type Len = $lenty:ty;
    const INITIAL_H: [$uint:ty; $statelen:expr] = $H:ident;
    const BLOCK_LEN: usize = $blocklen:expr;
    const DIGEST_LEN: usize = $digestlen:expr;
    fn compress = $compressfn:ident;
  ) => {
    pub struct $algo
    {
      h: [$uint; $statelen],
      block: [u8; $blocklen],
      len: u64,
      blocklen: usize,
    }

    impl $algo
    {
      pub const fn new() -> Self
      {
        Self {
          h: $H,
          block: [0; $blocklen],
          len: 0,
          blocklen: 0,
        }
      }

      pub fn new_boxed() -> Box<Self>
      {
        let mut ctx: Box<MaybeUninit<Self>> = Box::new_uninit();
        unsafe { ctx.assume_init_mut() }.reset();
        unsafe { ctx.assume_init() }
      }

      pub fn reset(&mut self)
      {
        self.h = $H;
        self.block = [0; $blocklen];
        self.len = 0;
        self.blocklen = 0;
      }

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

      pub fn finish(&mut self) -> [u8; $digestlen]
      {
        let mut output = [0; $digestlen];
        self.finish_into(&mut output);
        output
      }

      pub fn finish_boxed(&mut self) -> Box<[u8]>
      {
        let mut output = unsafe { Box::new_uninit_slice($digestlen).assume_init() };
        self.finish_into(&mut output);
        output
      }

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
        self.block[($blocklen - 8) .. $blocklen].copy_from_slice(self.len.as_ne_bytes());
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

      pub fn oneshot(data: &[u8]) -> [u8; $digestlen]
      {
        let mut ctx = Self::new();
        ctx.update(data);
        ctx.finish()
      }

      pub fn oneshot_boxed(data: &[u8]) -> Box<[u8]>
      {
        let mut ctx = Self::new();
        ctx.update(data);
        ctx.finish_boxed()
      }

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
    struct Sha1;
    type Len = u64;
    const INITIAL_H: [u32; 5] = H1;
    const BLOCK_LEN: usize = 64;
    const DIGEST_LEN: usize = 20;
    fn compress = sha1_compress_generic;
}

impl_sha! {
    struct Sha224;
    type Len = u64;
    const INITIAL_H: [u32; 8] = H224;
    const BLOCK_LEN: usize = 64;
    const DIGEST_LEN: usize = 28;
    fn compress = sha256_compress_generic;
}

impl_sha! {
    struct Sha256;
    type Len = u64;
    const INITIAL_H: [u32; 8] = H256;
    const BLOCK_LEN: usize = 64;
    const DIGEST_LEN: usize = 32;
    fn compress = sha256_compress_generic;
}

impl_sha! {
    struct Sha384;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H384;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 48;
    fn compress = sha512_compress_generic;
}

impl_sha! {
    struct Sha512;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H512;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 64;
    fn compress = sha512_compress_generic;
}

impl_sha! {
    struct Sha512_224;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H512_224;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 28;
    fn compress = sha512_compress_generic;
}

impl_sha! {
    struct Sha512_256;
    type Len = u128;
    const INITIAL_H: [u64; 8] = H512_256;
    const BLOCK_LEN: usize = 128;
    const DIGEST_LEN: usize = 32;
    fn compress = sha512_compress_generic;
}
