#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/aesni_intel_bindings.rs"));

use crate::Aes;

pub fn set_encrypt_key<const V: Aes>(key: &[u8], keysched: &mut [u8]) {
    assert!(key.len() == V.key_length());
    assert!(keysched.len() == V.expanded_key_length());

    let mut out = AES_KEY::default();
    unsafe { AES_set_encrypt_key(key.as_ptr(), V.bits() as _, &mut out) };
    keysched.clone_from_slice(&out.KEY[0..V.expanded_key_length()]);
}

pub fn set_decrypt_key<const V: Aes>(key: &[u8], keysched: &mut [u8]) {
    assert!(key.len() == V.key_length());
    assert!(keysched.len() == V.expanded_key_length());

    let mut out = AES_KEY::default();
    unsafe { AES_set_decrypt_key(key.as_ptr(), V.bits() as _, &mut out) };
    keysched.clone_from_slice(&out.KEY[0..V.expanded_key_length()]);
}
