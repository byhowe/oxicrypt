#![no_std]
#![feature(num_as_ne_bytes)]

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(test))]
#[panic_handler]
fn panic_handler(_panic: &core::panic::PanicInfo<'_>) -> !
{
  loop {}
}

pub mod sha;
