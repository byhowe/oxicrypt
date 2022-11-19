#![warn(incomplete_features)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]

mod aes;

pub use aes::Aes;
pub use aes::AesVectors;

pub(crate) struct BytesReader<'a> {
    buffer: &'a [u8],
    index: usize,
}

impl<'a> BytesReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, index: 0 }
    }

    pub fn next_n<const N: usize>(&mut self) -> &[u8] {
        let slice = &self.buffer[self.index..self.index + N];
        self.index += N;
        slice
    }
}
