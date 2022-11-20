#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/aesni_intel_bindings.rs"));

use crate::Aes;

#[repr(align(16))]
struct Keysched([u8; 1024]);

static mut KEYSCHED: Keysched = Keysched([0; 1024]);

pub fn expand_key<const V: Aes>(key: &[u8], keysched: &mut [u8]) {
    assert!(key.len() == V.key_length());
    assert!(keysched.len() == V.expanded_key_length());

    unsafe { KEYSCHED.0[0..V.expanded_key_length()].clone_from_slice(keysched) }

    unsafe {
        match V {
            Aes::Aes128 => AES_128_Key_Expansion(key.as_ptr(), KEYSCHED.0.as_mut_ptr()),
            Aes::Aes192 => AES_192_Key_Expansion(key.as_ptr(), KEYSCHED.0.as_mut_ptr()),
            Aes::Aes256 => AES_256_Key_Expansion(key.as_ptr(), KEYSCHED.0.as_mut_ptr()),
        }
    }

    unsafe { keysched.clone_from_slice(&KEYSCHED.0[0..V.expanded_key_length()]) }
}
