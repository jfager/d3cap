use std::hash::Hash;
use std::fmt;
use std::fmt::{Show,Formatter};

use rustc_serialize::hex::FromHex;
use rustc_serialize::{Encoder,Encodable};

fixed_vec!(MacAddr, u8, 6);

impl Show for MacAddr {
    fn fmt(&self, fo: &mut Formatter) -> fmt::Result {
        let &MacAddr(a) = self;
        write!(fo, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               a[0], a[1], a[2], a[3], a[4], a[5])
    }
}

impl<E,S: Encoder<E>> Encodable<S, E> for MacAddr {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        s.emit_str(self.to_string().as_slice())
    }
}

impl MacAddr {
    pub fn from_string(mac: &str) -> Option<MacAddr> {
        let v: Vec<&str> = mac.split(':').collect();
        if v.len() == 6 {
            let mut out = [0, ..6];
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

#[packed]
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
