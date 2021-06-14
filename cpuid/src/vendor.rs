// https://wiki.osdev.org/CPUID
// https://www.sandpile.org/x86/cpuid.htm#level_0000_0000h
pub enum Vendor
{
  /// `GenuineIntel' 	Intel processor
  Intel = 0,
  /// `AuthenticAMD' 	AMD processor
  AMD,
  /// `AMDisbetter!'  Early engineering samples of AMD K5 processor
  OldAMD,
  /// `UMC UMC UMC ' 	UMC processor
  UMC,
  /// `HygonGenuine'  Hygon processor
  Hygon,
  /// `CyrixInstead' 	Cyrix processor
  Cyrix,
  /// `NexGenDriven' 	NexGen processor
  NexGen,
  /// `CentaurHauls' 	Centaur processor
  Centaur,
  /// `RiseRiseRise' 	Rise Technology processor
  Rise,
  /// `SiS SiS SiS ' 	SiS processor
  SiS,
  /// `GenuineTMx86' 	Transmeta processor
  Transmeta,
  /// `Geode by NSC' 	National Semiconductor processor
  NSC,
}

impl Vendor
{
  pub const fn get_from_vendor_str(vendor_str: &[u8; 12]) -> Option<Self>
  {
    match vendor_str {
      | b"GenuineIntel" => Some(Self::Intel),
      | b"AuthenticAMD" => Some(Self::AMD),
      | b"AMDisbetter!" => Some(Self::OldAMD),
      | b"UMC UMC UMC " => Some(Self::UMC),
      | b"HygonGenuine" => Some(Self::Hygon),
      | b"CyrixInstead" => Some(Self::Cyrix),
      | b"NexGenDriven" => Some(Self::NexGen),
      | b"CentaurHauls" => Some(Self::Centaur),
      | b"RiseRiseRise" => Some(Self::Rise),
      | b"SiS SiS SiS " => Some(Self::SiS),
      | b"GenuineTMx86" => Some(Self::Transmeta),
      | b"Geode by NSC" => Some(Self::NSC),
      | _ => None,
    }
  }

  #[rustfmt::skip]
  pub const fn vendor_str(&self) -> &'static str
  {
    match self {
      | Self::Intel     => "GenuineIntel",
      | Self::AMD       => "AuthenticAMD",
      | Self::OldAMD    => "AMDisbetter!",
      | Self::UMC       => "UMC UMC UMC ",
      | Self::Hygon     => "HygonGenuine",
      | Self::Cyrix     => "CyrixInstead",
      | Self::NexGen    => "NexGenDriven",
      | Self::Centaur   => "CentaurHauls",
      | Self::Rise      => "RiseRiseRise",
      | Self::SiS       => "SiS SiS SiS ",
      | Self::Transmeta => "GenuineTMx86",
      | Self::NSC       => "Geode by NSC",
    }
  }
}
