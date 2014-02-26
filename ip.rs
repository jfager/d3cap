use std::hash::Hash;
use std::fmt;
use std::fmt::{Show,Formatter};

fixed_vec!(IP4Addr, u8, 4)

impl Show for IP4Addr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let &IP4Addr(a) = self;
        write!(f.buf, "{}.{}.{}.{}", a[0] as uint, a[1] as uint, a[2] as uint, a[3] as uint)
    }
}

#[packed]
pub struct IP4Header {
    ver_ihl: u8,
    dscp_ecn: u8,
    len: u16,
    ident: u16,
    flags_frag: u16,
    ttl: u8,
    proto: u8,
    hchk: u16,
    src: IP4Addr,
    dst: IP4Addr,
}


fixed_vec!(IP6Addr, u16, 8)

impl Show for IP6Addr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let &IP6Addr(a) = self;
        match a {
            //ip4-compatible
            [0,0,0,0,0,0,g,h] => {
                write!(f.buf, "::{}.{}.{}.{}",
                       (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8)
            }

            // ip4-mapped address
            [0,0,0,0,0,0xFFFF,g,h] => {
                write!(f.buf, "::FFFF:{}.{}.{}.{}",
                       (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8)
            }

            [a,b,c,d,e,f_,g,h] => {
                write!(f.buf, "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                       a, b, c, d, e, f_, g, h)
            }
        }
    }
}

#[packed]
pub struct IP6Header {
    ver_tc_fl: u32,
    len: u16,
    nxthdr: u8,
    hoplim: u8,
    src: IP6Addr,
    dst: IP6Addr
}
