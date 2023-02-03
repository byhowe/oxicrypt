#![no_std]
#![feature(const_fn_fn_ptr_basics)]

use oxicrypt::Control;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> ! { loop {} }

#[allow(non_camel_case_types)]
pub type oxi_implementation_t = oxicrypt::Implementation;

#[no_mangle]
pub unsafe extern "C" fn oxi_ctl_set_global_implementation(implementation: oxi_implementation_t)
{
    Control::set_global_implementation(implementation)
}

#[no_mangle]
pub unsafe extern "C" fn oxi_ctl_get_global_implementation() -> oxi_implementation_t
{
    Control::get_global_implementation()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_impl_fastest() -> oxi_implementation_t
{
    oxi_implementation_t::fastest()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_impl_fastest_rt() -> oxi_implementation_t
{
    oxi_implementation_t::fastest_rt()
}

#[no_mangle]
pub unsafe extern "C" fn oxi_impl_is_available(bits: oxi_implementation_t) -> bool
{
    oxi_implementation_t::is_available(bits)
}

pub mod aes;
pub mod hmac;
pub mod sha;
