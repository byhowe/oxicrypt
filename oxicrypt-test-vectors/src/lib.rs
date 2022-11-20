#![warn(incomplete_features)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(slice_as_chunks)]

mod aes;

#[cfg(feature = "generate")]
mod aesni_intel;

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

#[cfg(feature = "generate")]
pub(crate) struct BytesWriter<'a> {
    buffer: &'a mut [u8],
    index: usize,
}

#[cfg(feature = "generate")]
impl<'a> BytesWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, index: 0 }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.buffer[self.index..self.index + data.len()].clone_from_slice(data);
        self.index += data.len();
    }

    pub fn n_written(&self) -> usize {
        self.index
    }
}
