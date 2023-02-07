#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", doc)))]
compile_error!("`oxicrypt_core::aesni` is only available for \"x86\" and \"x86_64\"");

mod decrypt;
mod encrypt;
mod expand_key;
mod inverse_key;

pub use decrypt::*;
pub use encrypt::*;
pub use expand_key::*;
pub use inverse_key::*;
