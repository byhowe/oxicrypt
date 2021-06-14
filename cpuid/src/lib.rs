#![no_std]
#![feature(stdsimd)]
#![feature(const_str_from_utf8_unchecked)]

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("This crate is only supported on the x86 architecture!");

mod vendor;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::mem;

pub use vendor::Vendor;

pub struct CpuInfo
{
  max_level: u32,
  vendor: Option<Vendor>,
}

impl Default for CpuInfo
{
  fn default() -> Self
  {
    Self {
      max_level: 0,
      vendor: None,
    }
  }
}

impl CpuInfo
{
  pub fn detect() -> Self
  {
    let mut info = Self::default();

    if !has_cpuid() {
      return info;
    }

    let CpuidResult {
      eax: max_level,
      ebx: vendor_str_p1,
      edx: vendor_str_p2,
      ecx: vendor_str_p3,
    } = unsafe { __cpuid(0x0000_0000) };
    info.max_level = max_level;
    info.vendor = Vendor::get_from_vendor_str(&unsafe {
      mem::transmute::<[u32; 3], [u8; 12]>([vendor_str_p1, vendor_str_p2, vendor_str_p3])
    });

    info
  }

  pub const fn is_known_cpu(&self) -> bool
  {
    self.vendor.is_some()
  }

  pub const fn vendor_str(&self) -> &str
  {
    match &self.vendor {
      | None => "Unknown",
      | Some(vendor) => vendor.vendor_str(),
    }
  }
}
