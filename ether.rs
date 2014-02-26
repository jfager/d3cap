use std::hash::Hash;
use std::fmt;
use std::fmt::{Show,Formatter};

fixed_vec!(MacAddr, u8, 6)

impl Show for MacAddr {
    fn fmt(&self, fo: &mut Formatter) -> fmt::Result {
        let &MacAddr(a) = self;
        write!(fo.buf, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               a[0], a[1], a[2], a[3], a[4], a[5])
    }
}

#[packed]
pub struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    typ: u16
}

//in big-endian order to match packet
pub static ETHERTYPE_ARP: u16 = 0x0608;
pub static ETHERTYPE_IP4: u16 = 0x0008;
pub static ETHERTYPE_IP6: u16 = 0xDD86;
pub static ETHERTYPE_802_1X: u16 = 0x8E88;
