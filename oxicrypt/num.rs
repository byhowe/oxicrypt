#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder
{
    Little,
    Big,
}

impl ByteOrder
{
    pub const fn le() -> Self { Self::Little }

    pub const fn be() -> Self { Self::Big }

    pub const fn ne() -> Self
    {
        #[cfg(target_endian = "big")]
        {
            Self::Big
        }
        #[cfg(target_endian = "little")]
        {
            Self::Little
        }
    }
}
