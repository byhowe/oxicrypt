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
    pub plaintext: [[u8; 16]; 8],
    pub ciphertext: [[u8; 16]; 8],
}
