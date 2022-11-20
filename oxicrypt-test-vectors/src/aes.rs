use crate::BytesReader;

#[cfg(feature = "generate")]
use {crate::BytesWriter, rand::RngCore, std::os::raw::c_uchar};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aes {
    Aes128,
    Aes192,
    Aes256,
}

impl Aes {
    pub const fn key_length(self) -> usize {
        match self {
            Aes::Aes128 => 16,
            Aes::Aes192 => 24,
            Aes::Aes256 => 32,
        }
    }

    pub const fn expanded_key_length(self) -> usize {
        match self {
            Aes::Aes128 => 176,
            Aes::Aes192 => 208,
            Aes::Aes256 => 240,
        }
    }

    #[cfg(feature = "generate")]
    pub const fn expansion_function(self) -> unsafe extern "C" fn(*const c_uchar, *mut c_uchar) {
        match self {
            Aes::Aes128 => crate::aesni_intel::AES_128_Key_Expansion,
            Aes::Aes192 => crate::aesni_intel::AES_192_Key_Expansion,
            Aes::Aes256 => crate::aesni_intel::AES_256_Key_Expansion,
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
    pub fn generate_random() -> AesVectors<V> {
        let mut rng = rand::thread_rng();
        let mut vectors = AesVectors::default();

        rng.fill_bytes(&mut vectors.key);
        rng.fill_bytes(&mut vectors.plaintext);

        unsafe { V.expansion_function()(vectors.key.as_ptr(), vectors.expanded_key.as_mut_ptr()) }

        vectors
    }

    #[cfg(feature = "generate")]
    pub fn write_to_bytes(&self, raw: &mut [u8]) {
        let mut buffer = BytesWriter::new(raw);

        buffer.write(&self.key);
        buffer.write(&self.expanded_key);
        buffer.write(&self.inversed_key);
        buffer.write(&self.plaintext);
        buffer.write(&self.ciphertext);
    }

    pub fn plaintext_chunks(&self) -> &[[u8; 8]] {
        let (chunks, _) = self.plaintext.as_chunks();
        chunks
    }

    pub fn ciphertext_chunks(&self) -> &[[u8; 8]] {
        let (chunks, _) = self.ciphertext.as_chunks();
        chunks
    }
}
