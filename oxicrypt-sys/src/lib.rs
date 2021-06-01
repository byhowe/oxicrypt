#![no_std]

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

#[cfg_attr(not(test), panic_handler)]
#[allow(dead_code)]
fn panic_handler(_panic: &core::panic::PanicInfo<'_>) -> !
{
  loop {}
}

pub mod sha;
