use std::slice::Chunks;

use crate::BytesReader;

#[cfg(feature = "generate")]
use {crate::BytesWriter, rand::RngCore};

const AES128_BIN: &[u8] = include_bytes!(env!("OXI_TEST_aes128.bin"));
const AES192_BIN: &[u8] = include_bytes!(env!("OXI_TEST_aes192.bin"));
const AES256_BIN: &[u8] = include_bytes!(env!("OXI_TEST_aes256.bin"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes {
    Aes128,
    Aes192,
    Aes256,
}

#[repr(align(16))]
struct AlignedKeysched([u8; 15 * 16]);

impl Aes {
    pub const fn bits(self) -> usize {
        match self {
            Aes::Aes128 => 128,
            Aes::Aes192 => 192,
            Aes::Aes256 => 256,
        }
    }

    pub const fn key_length(self) -> usize {
        self.bits() / 8
    }

    pub const fn rounds(self) -> usize {
        match self {
            Aes::Aes128 => 10,
            Aes::Aes192 => 12,
            Aes::Aes256 => 14,
        }
    }

    pub const fn expanded_key_length(self) -> usize {
        (self.rounds() + 1) * 16
    }

    const fn bin(self) -> &'static [u8] {
        match self {
            Aes::Aes128 => AES128_BIN,
            Aes::Aes192 => AES192_BIN,
            Aes::Aes256 => AES256_BIN,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AesVectors<const V: Aes>
where
    [(); V.key_length()]:,
    [(); V.expanded_key_length()]:,
{
    pub key: [u8; V.key_length()],
    pub expanded_key: [u8; V.expanded_key_length()],
    pub inversed_key: [u8; V.expanded_key_length()],
    pub plaintext: [u8; 16 * 8],
    pub ciphertext: [u8; 16 * 8],
}

impl<const V: Aes> Default for AesVectors<V>
where
    [(); V.key_length()]:,
    [(); V.expanded_key_length()]:,
{
    fn default() -> Self {
        Self {
            key: [0; V.key_length()],
            expanded_key: [0; V.expanded_key_length()],
            inversed_key: [0; V.expanded_key_length()],
            plaintext: [0; 16 * 8],
            ciphertext: [0; 16 * 8],
        }
    }
}

impl<const V: Aes> AesVectors<V>
where
    [(); V.key_length()]:,
    [(); V.expanded_key_length()]:,
{
    pub const fn size() -> usize {
        V.key_length() + V.expanded_key_length() + V.expanded_key_length() + 16 * 8 + 16 * 8
    }

    pub fn read_from_bytes(raw: &[u8]) -> AesVectors<V> {
        let mut vectors = AesVectors::default();
        let mut buffer = BytesReader::new(raw);

        vectors
            .key
            .clone_from_slice(buffer.next_n::<{ V.key_length() }>());
        vectors
            .expanded_key
            .clone_from_slice(buffer.next_n::<{ V.expanded_key_length() }>());
        vectors
            .inversed_key
            .clone_from_slice(buffer.next_n::<{ V.expanded_key_length() }>());
        vectors
            .plaintext
            .clone_from_slice(buffer.next_n::<{ 16 * 8 }>());
        vectors
            .ciphertext
            .clone_from_slice(buffer.next_n::<{ 16 * 8 }>());

        vectors
    }

    #[cfg(feature = "generate")]
    pub fn set_random(&mut self) {
        let mut rng = rand::thread_rng();

        rng.fill_bytes(&mut self.key);
        rng.fill_bytes(&mut self.plaintext);

        crate::aesni_intel::set_encrypt_key::<V>(&self.key, &mut self.expanded_key);
        crate::aesni_intel::set_decrypt_key::<V>(&self.key, &mut self.inversed_key);
        let mut alignedkeysched = AlignedKeysched([0; 15 * 16]);
        alignedkeysched.0[0..V.expanded_key_length()].clone_from_slice(&self.expanded_key);
        crate::aesni_intel::encrypt::<V>(&self.plaintext, &mut self.ciphertext, &alignedkeysched.0);
    }

    #[cfg(feature = "generate")]
    pub fn write_to_bytes(&self, raw: &mut [u8]) -> usize {
        let mut buffer = BytesWriter::new(raw);

        buffer.write(&self.key);
        buffer.write(&self.expanded_key);
        buffer.write(&self.inversed_key);
        buffer.write(&self.plaintext);
        buffer.write(&self.ciphertext);

        buffer.n_written()
    }

    pub fn plaintext_chunks(&self) -> &[[u8; 16]] {
        let (chunks, _) = self.plaintext.as_chunks();
        chunks
    }

    pub fn ciphertext_chunks(&self) -> &[[u8; 16]] {
        let (chunks, _) = self.ciphertext.as_chunks();
        chunks
    }
}

pub struct AesVectorsIterator<const V: Aes> {
    chunks: Chunks<'static, u8>,
}

impl<const V: Aes> AesVectorsIterator<V>
where
    [(); V.key_length()]:,
    [(); V.expanded_key_length()]:,
{
    pub fn new() -> Self {
        let chunks = (V.bin()[4..]).chunks(AesVectors::<V>::size());
        Self { chunks }
    }
}

impl<const V: Aes> Iterator for AesVectorsIterator<V>
where
    [(); V.key_length()]:,
    [(); V.expanded_key_length()]:,
{
    type Item = AesVectors<V>;

    fn next(&mut self) -> Option<Self::Item> {
        self.chunks
            .next()
            .map(|b| AesVectors::<V>::read_from_bytes(b))
    }
}
