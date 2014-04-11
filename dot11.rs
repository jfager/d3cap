use ether::{MacAddr};

//For possible reference:
//https://github.com/simsong/tcpflow/blob/master/src/wifipcap/ieee802_11_radio.h
#[packed]
pub struct RadiotapHeader {
    pub it_version: u8,
    pub it_pad: u8,
    pub it_len: u16,
    pub it_present: u32
}

pub static TSFT: uint = 0;
pub static FLAGS: uint = 1;
pub static RATE: uint = 2;
pub static CHANNEL: uint = 3;
pub static FHSS: uint = 4;
pub static ANTENNA_SIGNAL: uint = 5;
pub static ANTENNA_NOISE: uint = 6;
pub static LOCK_QUALITY: uint = 7;
pub static TX_ATTENUATION: uint  = 8;
pub static DB_TX_ATTENUATION: uint  = 9;
pub static DBM_TX_POWER: uint  = 10;
pub static ANTENNA: uint = 11;
pub static DB_ANTENNA_SIGNAL: uint = 12;
pub static DB_ANTENNA_NOISE: uint  = 13;
pub static RX_FLAGS: uint  = 14;
pub static MCS: uint = 19;
pub static A_MPDU_STATUS: uint = 20;
pub static VHT: uint = 21;
pub static MORE_IT_PRESENT: uint  = 31;

impl RadiotapHeader {
    pub fn has_field(&self, field: uint) -> bool {
        self.it_present & (1 << field) > 0
    }
}

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
