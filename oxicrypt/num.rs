mod sealed
{
    pub trait Sealed {}
}
use sealed::Sealed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder
{
    Little,
    Big,
}

#[const_trait]
pub trait Endian: Sealed
{
    fn endian() -> ByteOrder;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Le {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Be {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ne {}

impl Sealed for Le {}
impl Sealed for Be {}
impl Sealed for Ne {}

impl const Endian for Le
{
    fn endian() -> ByteOrder { ByteOrder::Little }
}

impl const Endian for Be
{
    fn endian() -> ByteOrder { ByteOrder::Big }
}

impl const Endian for Ne
{
    fn endian() -> ByteOrder
    {
        #[cfg(target_endian = "big")]
        return ByteOrder::Big;

        #[cfg(target_endian = "little")]
        return ByteOrder::Little;
    }
}
