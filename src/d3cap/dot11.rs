use ether::{MacAddr};

// For possible reference:
// https://github.com/simsong/tcpflow/blob/master/src/wifipcap/wifipcap.h
// For definitive reference:
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf
#[packed]
pub struct Dot11MacBaseHeader {
    pub fr_ctrl: FrameControl,
    pub dur_id: u16,
    pub addr1: MacAddr,
}

#[packed]
pub struct FrameControl {
    pub ty: u8,
    pub flags: u8,
}

impl FrameControl {
    /// When this is non-zero, the packet is bogus; however, being 0 is not sufficient
    /// to imply that the packet is good.  From verifying with Wireshark and reading
    /// around, bogus packets can be pretty common (and are on my network and card), so
    /// you need to be able to handle them.
    pub fn protocol_version(&self) -> u8 {
        self.ty & 0b00000011
    }
    pub fn frame_type(&self) -> u8 {
        (self.ty & 0b00001100) >> 2
    }
    pub fn frame_subtype(&self) -> u8 {
        (self.ty & 0b11110000) >> 4
    }
}

#[packed]
pub struct Dot11MacFullHeader {
    base: Dot11MacBaseHeader,
    addr2: MacAddr,
    addr3: MacAddr,
    seq_ctrl: u16,
    addr4: MacAddr,
    qos_ctrl: u16,
    ht_ctrl: u32
}
