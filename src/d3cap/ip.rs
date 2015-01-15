use std::hash::Hash;

use rustc_serialize::{Encodable, Encoder};

fixed_vec!(IP4Addr, u8, 4);

impl ToString for IP4Addr {
    fn to_string(&self) -> String {
        let &IP4Addr(a) = self;
        format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
    }
}

impl Encodable for IP4Addr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.to_string()[])
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

impl ToString for IP6Addr {
    fn to_string(&self) -> String {
        let &IP6Addr(a) = self;
        match a {
            //ip4-compatible
            [0,0,0,0,0,0,g,h] => {
                format!("::{}.{}.{}.{}",
                        (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8)
            }

            // ip4-mapped address
            [0,0,0,0,0,0xFFFF,g,h] => {
                format!("::FFFF:{}.{}.{}.{}",
                        (g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8)
            }

            [a,b,c,d,e,f_,g,h] => {
                format!("{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                        a, b, c, d, e, f_, g, h)
            }
        }
    }
}

impl Encodable for IP6Addr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.to_string()[])
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
