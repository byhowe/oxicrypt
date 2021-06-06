use cfg_if::cfg_if;

mod aes_generic;

pub use aes_generic::aes128_decrypt_generic;
pub use aes_generic::aes128_encrypt_generic;
pub use aes_generic::aes128_expand_key_generic;
pub use aes_generic::aes128_inverse_key_generic;
pub use aes_generic::aes192_decrypt_generic;
pub use aes_generic::aes192_encrypt_generic;
pub use aes_generic::aes192_expand_key_generic;
pub use aes_generic::aes192_inverse_key_generic;
pub use aes_generic::aes256_decrypt_generic;
pub use aes_generic::aes256_encrypt_generic;
pub use aes_generic::aes256_expand_key_generic;
pub use aes_generic::aes256_inverse_key_generic;

cfg_if! {
  if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    mod aes_x86_aesni;

    pub use aes_x86_aesni::aes128_expand_key_x86_aesni;
    pub use aes_x86_aesni::aes192_expand_key_x86_aesni;
    pub use aes_x86_aesni::aes256_expand_key_x86_aesni;

    pub use aes_x86_aesni::aes128_inverse_key_x86_aesni;
    pub use aes_x86_aesni::aes192_inverse_key_x86_aesni;
    pub use aes_x86_aesni::aes256_inverse_key_x86_aesni;

    pub use aes_x86_aesni::aes128_encrypt_x86_aesni;
    pub use aes_x86_aesni::aes192_encrypt_x86_aesni;
    pub use aes_x86_aesni::aes256_encrypt_x86_aesni;

    pub use aes_x86_aesni::aes128_decrypt_x86_aesni;
    pub use aes_x86_aesni::aes192_decrypt_x86_aesni;
    pub use aes_x86_aesni::aes256_decrypt_x86_aesni;
  }
}
