use ether::{MacAddr};

//For possible reference:
//https://github.com/simsong/tcpflow/blob/master/src/wifipcap/ieee802_11_radio.h
#[packed]
pub struct RadiotapHeader {
    it_version: u8,
    it_pad: u8,
    it_len: u16,
    it_present: u32
}

// For possible reference:
// https://github.com/simsong/tcpflow/blob/master/src/wifipcap/wifipcap.h
// For definitive reference:
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf
#[packed]
pub struct Dot11MacBaseHeader {
    fr_ctrl: u16,
    dur_id: u16,
    addr1: MacAddr,
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
