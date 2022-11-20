#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/aesni_intel_bindings.rs"));

use crate::Aes;

pub fn expand_key<const V: Aes>(key: &[u8], keysched: &mut [u8]) {
    assert!(key.len() == V.key_length());
    assert!(keysched.len() == V.expanded_key_length());

    unsafe {
        match V {
            Aes::Aes128 => AES_128_Key_Expansion(key.as_ptr(), keysched.as_mut_ptr()),
            Aes::Aes192 => AES_192_Key_Expansion(key.as_ptr(), keysched.as_mut_ptr()),
            Aes::Aes256 => AES_256_Key_Expansion(key.as_ptr(), keysched.as_mut_ptr()),
        }
    }
}
