#![no_std]

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("This crate is only supported on the x86 architecture!");
