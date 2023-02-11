#[cfg(not(any(target_arch = "arm", target_arch = "aarch64", doc)))]
compile_error!("`oxicrypt_core::aes_arm` is only available for \"arm\" and \"aarch64\"");

mod decrypt;
mod encrypt;

pub use decrypt::*;
pub use encrypt::*;
