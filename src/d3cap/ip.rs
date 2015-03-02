use std::fmt::{Display,Error,Formatter};
use std::{net};

use rustc_serialize::{Encodable, Encoder};

pub trait AsStdIpAddr {
    fn as_std_ip(&self) -> net::IpAddr;
}


#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct IP4Addr([u8; 4]);

impl AsStdIpAddr for IP4Addr {
    fn as_std_ip(&self) -> net::IpAddr {
        let &IP4Addr(a) = self;
        net::IpAddr::new_v4(a[0], a[1], a[2], a[3])
    }
}

impl Display for IP4Addr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let &IP4Addr(a) = self;
        f.write_str(&format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
    }
}

impl Encodable for IP4Addr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.to_string())
    }
}


#[repr(packed)]
pub struct IP4Header {
    pub ver_ihl: u8,
    pub dscp_ecn: u8,
    pub len: u16,
    pub ident: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub proto: u8,
    pub hchk: u16,
    pub src: IP4Addr,
    pub dst: IP4Addr,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct IP6Addr([u16; 8]);

impl AsStdIpAddr for IP6Addr {
    fn as_std_ip(&self) -> net::IpAddr {
        let &IP6Addr(a) = self;
        net::IpAddr::new_v6(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
    }
}

impl Display for IP6Addr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let &IP6Addr(a) = self;
        match a {
            //ip4-compatible
            [0,0,0,0,0,0,g,h] => {
                f.write_str(&format!("::{}.{}.{}.{}",
                                     (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8))
            }

            // ip4-mapped address
            [0,0,0,0,0,0xFFFF,g,h] => {
                f.write_str(&format!("::FFFF:{}.{}.{}.{}",
                                     (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8))
            }

            [a,b,c,d,e,f_,g,h] => {
                f.write_str(&format!("{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                                     a, b, c, d, e, f_, g, h))
            }
        }
    }
}

impl Encodable for IP6Addr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.to_string())
    }
}


#[repr(packed)]
pub struct IP6Header {
    pub ver_tc_fl: u32,
    pub len: u16,
    pub nxthdr: u8,
    pub hoplim: u8,
    pub src: IP6Addr,
    pub dst: IP6Addr
}
