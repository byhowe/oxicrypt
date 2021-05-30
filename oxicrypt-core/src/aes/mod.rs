use cfg_if::cfg_if;

cfg_if! {
  if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    mod aes128_encrypt_x86_aesni;
    mod aes128_decrypt_x86_aesni;

    pub use aes128_decrypt_x86_aesni::aes128_decrypt8_x86_aesni;
    pub use aes128_decrypt_x86_aesni::aes128_decrypt_x86_aesni;
    pub use aes128_decrypt_x86_aesni::aes128_expand_decrypt_key_x86_aesni;
    pub use aes128_encrypt_x86_aesni::aes128_encrypt8_x86_aesni;
    pub use aes128_encrypt_x86_aesni::aes128_encrypt_x86_aesni;
    pub use aes128_encrypt_x86_aesni::aes128_expand_encrypt_key_x86_aesni;
  }
}

mod aes128_decrypt_generic;
mod aes128_encrypt_generic;

pub use aes128_decrypt_generic::aes128_decrypt8_generic;
pub use aes128_decrypt_generic::aes128_decrypt_generic;
pub use aes128_decrypt_generic::aes128_expand_decrypt_key_generic;
pub use aes128_encrypt_generic::aes128_encrypt8_generic;
pub use aes128_encrypt_generic::aes128_encrypt_generic;
pub use aes128_encrypt_generic::aes128_expand_encrypt_key_generic;
