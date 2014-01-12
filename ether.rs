fixed_vec!(MacAddr, u8, 6)

impl ToStr for MacAddr {
    fn to_str(&self) -> ~str {
        let f = |x: u8,y| x.to_str_radix(y);
        let &MacAddr(a) = self;
        return format!("{}:{}:{}:{}:{}:{}",
                       f(a[0], 16), f(a[1], 16), f(a[2], 16),
                       f(a[3], 16), f(a[4], 16), f(a[5], 16)
                      );
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
