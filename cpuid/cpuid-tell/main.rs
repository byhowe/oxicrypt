fn main()
{
  let info = cpuid::CpuInfo::detect();
  println!("Vendor String is `{}'", info.vendor_str());
}
