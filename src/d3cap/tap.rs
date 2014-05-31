#![allow(dead_code)]

use std::mem::size_of;
use util::trans_off;

//For possible reference:
//https://github.com/simsong/tcpflow/blob/master/src/wifipcap/ieee802_11_radio.h

#[packed]
pub struct RadiotapHeader {
    pub it_version: u8, // 8 -> 1
    pub it_pad: u8, // 8 -> 1
    pub it_len: u16, // 16 -> 2
    pub it_present: ItPresent // 32 -> 4
}
//size_of should == 8

bitflags!(flags ItPresent: u32 {
    static TSFT              = 1 << 0,
    static FLAGS             = 1 << 1,
    static RATE              = 1 << 2,
    static CHANNEL           = 1 << 3,
    static FHSS              = 1 << 4,
    static ANTENNA_SIGNAL    = 1 << 5,
    static ANTENNA_NOISE     = 1 << 6,
    static LOCK_QUALITY      = 1 << 7,
    static TX_ATTENUATION    = 1 << 8,
    static DB_TX_ATTENUATION = 1 << 9,
    static DBM_TX_POWER      = 1 << 10,
    static ANTENNA           = 1 << 11,
    static DB_ANTENNA_SIGNAL = 1 << 12,
    static DB_ANTENNA_NOISE  = 1 << 13,
    static RX_FLAGS          = 1 << 14,
    static TX_FLAGS          = 1 << 15,
    static RTS_RETRIES       = 1 << 16,
    static DATA_RETRIES      = 1 << 17,
    static MCS               = 1 << 19,
    static A_MPDU_STATUS     = 1 << 20,
    static VHT               = 1 << 21,
    static MORE_IT_PRESENT   = 1 << 31,

    static COMMON_A          = TSFT.bits
                             | FLAGS.bits
                             | RATE.bits
                             | CHANNEL.bits
                             | ANTENNA_SIGNAL.bits
                             | ANTENNA_NOISE.bits
                             | ANTENNA.bits,

    static COMMON_B          = TSFT.bits
                             | FLAGS.bits
                             | CHANNEL.bits
                             | ANTENNA_SIGNAL.bits
                             | ANTENNA_NOISE.bits
                             | ANTENNA.bits
                             | MCS.bits
})

pub struct Tsft {
    pub timer_micros: u64
}

bitflags!(flags Flags: u8 {
    static DuringCFP     = 0x01,
    static ShortPreamble = 0x02,
    static EncryptWep    = 0x04,
    static Fragmentation = 0x08,
    static IncludesFCS   = 0x10,
    static HasPadding    = 0x20,
    static FailedFCSChk  = 0x40,
    static ShortGuard    = 0x80
})

pub struct Rate {
    pub in_500kbps: u8
}

bitflags!(flags ChannelFlags: u16 {
    static Turbo       = 0x0010,
    static CCK         = 0x0020,
    static OFDM        = 0x0040,
    static Ghz2        = 0x0080,
    static Ghz5        = 0x0100,
    static PsvScan     = 0x0200,
    static DynCCK_OFDM = 0x0400,
    static GFSK        = 0x0800
})

pub struct Channel {
    pub mhz: u16,
    pub flags: ChannelFlags
}

pub struct AntennaSignal {
    pub dBm: i8
}

pub struct AntennaNoise {
    pub dBm: i8
}

pub struct Antenna {
    pub idx: u8
}

pub struct Mcs {
    pub known: u8,
    pub flags: u8,
    pub mcs: u8
}

// For now just predefining a few types of packets I actually see with my setup,
// rather than defining a general parser.
#[packed]
pub struct CommonA {
    pub tsft: Tsft,
    pub flags: Flags,
    pub rate: Rate,
    pub channel: Channel,
    pub antenna_signal: AntennaSignal,
    pub antenna_noise: AntennaNoise,
    pub antenna: Antenna
}

impl CommonA {
    pub fn parse<'a>(hdr: &'a RadiotapHeader) -> Option<&'a CommonA> {
        let sz = size_of::<RadiotapHeader>() + size_of::<CommonA>();
        if hdr.it_present == COMMON_A
        && hdr.it_len as uint >= sz {
            let out: &CommonA = unsafe { trans_off(hdr, size_of::<CommonA>() as int) };
            Some(out)
        } else {
            None
        }
    }
}

#[packed]
pub struct CommonB {
    pub tsft: Tsft,
    pub flags: Flags,
    pub channel: Channel,
    pub antenna_signal: AntennaSignal,
    pub antenna_noise: AntennaNoise,
    pub antenna: Antenna,
    pub mcs: Mcs
}

impl CommonB {
    pub fn parse<'a>(hdr: &'a RadiotapHeader) -> Option<&'a CommonB> {
        let sz = size_of::<RadiotapHeader>() + size_of::<CommonB>();
        if hdr.it_present == COMMON_B
        && hdr.it_len as uint >= sz {
            let out: &CommonB = unsafe { trans_off(hdr, size_of::<CommonB>() as int) };
            Some(out)
        } else {
            None
        }
    }
}




impl RadiotapHeader {
    pub fn has_field(&self, fld: ItPresent) -> bool {
        self.it_present.contains(fld)
    }
}
