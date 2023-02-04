#![allow(unused_imports)]
use std_detect::is_aarch64_feature_detected;
use std_detect::is_arm_feature_detected;
use std_detect::is_x86_feature_detected;

/// CPU features used by the library.
pub enum Feature
{
    /// x86 aesni used for hardware accelarated aes encryption and decryption.
    Aesni,
    /// ARM aes used for hardware accelarated aes encryption and decryption.
    ArmAes,
}

impl Feature
{
    #[allow(unreachable_code)]
    #[inline(always)]
    pub fn is_available(self) -> bool
    {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return match self {
                | Self::Aesni => is_x86_feature_detected!("aes"),
                | Self::ArmAes => false,
            };
        }

        #[cfg(target_arch = "arm")]
        {
            return match self {
                | Self::Aesni => false,
                | Self::ArmAes => is_arm_feature_detected!("aes"),
            };
        }

        #[cfg(target_arch = "aarch64")]
        {
            return match self {
                | Self::Aesni => false,
                | Self::ArmAes => is_aarch64_feature_detected!("aes"),
            };
        }

        false
    }
}
