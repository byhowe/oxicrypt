use cfg_if::cfg_if;

cfg_if! {
  if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    mod aes128_encrypt_x86_aesni;
    mod aes128_decrypt_x86_aesni;

    pub use aes128_encrypt_x86_aesni::aes128_expand_encrypt_key_x86_aesni;
    pub use aes128_encrypt_x86_aesni::aes128_encrypt_x86_aesni;
    pub use aes128_encrypt_x86_aesni::aes128_encrypt8_x86_aesni;
    pub use aes128_decrypt_x86_aesni::aes128_expand_decrypt_key_x86_aesni;
    pub use aes128_decrypt_x86_aesni::aes128_decrypt_x86_aesni;
    pub use aes128_decrypt_x86_aesni::aes128_decrypt8_x86_aesni;
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

#[inline(always)]
pub unsafe fn aes128_expand_encrypt_key_autodetect(key: *const u8, round_keys: *mut u8)
{
  cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
      if is_x86_feature_detected!("aes") {
        aes128_expand_encrypt_key_x86_aesni(key, round_keys);
      } else {
        aes128_expand_encrypt_key_generic(key, round_keys);
      }
    } else {
      aes128_expand_encrypt_key_generic(key, round_keys);
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_encrypt_autodetect(block: *mut u8, round_keys: *const u8)
{
  cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
      if is_x86_feature_detected!("aes") {
        aes128_encrypt_x86_aesni(block, round_keys);
      } else {
        aes128_encrypt_generic(block, round_keys);
      }
    } else {
      aes128_encrypt_generic(block, round_keys);
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_encrypt8_autodetect(blocks: *mut u8, round_keys: *const u8)
{
  cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
      if is_x86_feature_detected!("aes") {
        aes128_encrypt8_x86_aesni(blocks, round_keys);
      } else {
        aes128_encrypt8_generic(blocks, round_keys);
      }
    } else {
      aes128_encrypt8_generic(blocks, round_keys);
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_expand_decrypt_key_autodetect(key: *const u8, round_keys: *mut u8)
{
  cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
      if is_x86_feature_detected!("aes") {
        aes128_expand_decrypt_key_x86_aesni(key, round_keys);
      } else {
        aes128_expand_decrypt_key_generic(key, round_keys);
      }
    } else {
      aes128_expand_decrypt_key_generic(key, round_keys);
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_decrypt_autodetect(block: *mut u8, round_keys: *const u8)
{
  cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
      if is_x86_feature_detected!("aes") {
        aes128_decrypt_x86_aesni(block, round_keys);
      } else {
        aes128_decrypt_generic(block, round_keys);
      }
    } else {
      aes128_decrypt_generic(block, round_keys);
    }
  }
}

#[inline(always)]
pub unsafe fn aes128_decrypt8_autodetect(blocks: *mut u8, round_keys: *const u8)
{
  cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
      if is_x86_feature_detected!("aes") {
        aes128_decrypt8_x86_aesni(blocks, round_keys);
      } else {
        aes128_decrypt8_generic(blocks, round_keys);
      }
    } else {
      aes128_decrypt8_generic(blocks, round_keys);
    }
  }
}
