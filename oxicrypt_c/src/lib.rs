#![no_std]
#![feature(const_fn_fn_ptr_basics)]

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> !
{
  loop {}
}

pub mod aes;
pub mod hmac;
pub mod sha;
