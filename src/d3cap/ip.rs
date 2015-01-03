use std::hash::Hash;
use std::fmt;
use std::fmt::{Show,Formatter};

use rustc_serialize::{Encodable, Encoder};

fixed_vec!(IP4Addr, u8, 4);

impl Show for IP4Addr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let &IP4Addr(a) = self;
        write!(f, "{}.{}.{}.{}", a[0] as uint, a[1] as uint, a[2] as uint, a[3] as uint)
    }
}

impl<E,S: Encoder<E>> Encodable<S, E> for IP4Addr {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        s.emit_str(self.to_string().as_slice())
    }
}

#[packed]
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


fixed_vec!(IP6Addr, u16, 8);

impl Show for IP6Addr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let &IP6Addr(a) = self;
        match a {
            //ip4-compatible
            [0,0,0,0,0,0,g,h] => {
                write!(f, "::{}.{}.{}.{}",
                       (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8)
            }

            // ip4-mapped address
            [0,0,0,0,0,0xFFFF,g,h] => {
                write!(f, "::FFFF:{}.{}.{}.{}",
                       (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8)
            }

            [a,b,c,d,e,f_,g,h] => {
                write!(f, "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                       a, b, c, d, e, f_, g, h)
            }
        }
    }
}

impl<E,S: Encoder<E>> Encodable<S, E> for IP6Addr {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        s.emit_str(self.to_string().as_slice())
    }
}

#[packed]
pub struct IP6Header {
    pub ver_tc_fl: u32,
    pub len: u16,
    pub nxthdr: u8,
    pub hoplim: u8,
    pub src: IP6Addr,
    pub dst: IP6Addr
}
