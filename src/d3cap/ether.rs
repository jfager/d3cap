use std::fmt::{Display, Error, Formatter};

use rustc_serialize::hex::FromHex;
use rustc_serialize::{Encoder,Encodable};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct MacAddr([u8; 6]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let &MacAddr(a) = self;
        f.write_str(&format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                             a[0], a[1], a[2], a[3], a[4], a[5]))
    }
}

impl Encodable for MacAddr {
    fn encode<S:Encoder> (&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.to_string())
    }
}

impl MacAddr {
    pub fn from_string(mac: &str) -> Option<MacAddr> {
        let v: Vec<_> = mac.split(':').collect();
        if v.len() == 6 {
            let mut out = [0; 6];
            for (i, s) in v.iter().enumerate() {
                match s.from_hex() {
                    Ok(ref hx) if hx.len() == 1 => out[i] = hx[0],
                    _ => return None
                }
            }
            Some(MacAddr(out))
        } else {
            None
        }
    }
}

#[repr(packed)]
#[derive(Debug)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub typ: u16
}

//in big-endian order to match packet
pub const ETHERTYPE_ARP: u16 = 0x0608;
pub const ETHERTYPE_IP4: u16 = 0x0008;
pub const ETHERTYPE_IP6: u16 = 0xDD86;
pub const ETHERTYPE_802_1X: u16 = 0x8E88;
