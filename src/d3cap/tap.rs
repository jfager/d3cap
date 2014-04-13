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
