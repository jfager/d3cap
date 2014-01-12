
fixed_vec!(IP4Addr, u8, 4)

impl ToStr for IP4Addr {
    fn to_str(&self) -> ~str {
        let &IP4Addr(a) = self;
        format!("{}.{}.{}.{}", a[0] as uint, a[1] as uint, a[2] as uint, a[3] as uint)
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

impl ToStr for IP6Addr {
    fn to_str(&self) -> ~str {
        let &IP6Addr(a) = self;
        match (a) {
            //ip4-compatible
            [0,0,0,0,0,0,g,h] => {
                format!("::{}.{}.{}.{}", (g >> 8) as u8, g as u8,
                        (h >> 8) as u8, h as u8)
            }

            // ip4-mapped address
            [0, 0, 0, 0, 0, 0xFFFF, g, h] => {
                format!("::FFFF:{}.{}.{}.{}", (g >> 8) as u8, g as u8,
                        (h >> 8) as u8, h as u8)
            }

            [a, b, c, d, e, f, g, h] => {
                format!("{}:{}:{}:{}:{}:{}:{}:{}", a, b, c, d, e, f, g, h)
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
