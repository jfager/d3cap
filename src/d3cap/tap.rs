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

bitflags!(ItPresent: u32 {
    TSFT              = 1 << 0,
    FLAGS             = 1 << 1,
    RATE              = 1 << 2,
    CHANNEL           = 1 << 3,
    FHSS              = 1 << 4,
    ANTENNA_SIGNAL    = 1 << 5,
    ANTENNA_NOISE     = 1 << 6,
    LOCK_QUALITY      = 1 << 7,
    TX_ATTENUATION    = 1 << 8,
    DB_TX_ATTENUATION = 1 << 9,
    DBM_TX_POWER      = 1 << 10,
    ANTENNA           = 1 << 11,
    DB_ANTENNA_SIGNAL = 1 << 12,
    DB_ANTENNA_NOISE  = 1 << 13,
    RX_FLAGS          = 1 << 14,
    TX_FLAGS          = 1 << 15,
    RTS_RETRIES       = 1 << 16,
    DATA_RETRIES      = 1 << 17,
    MCS               = 1 << 19,
    A_MPDU_STATUS     = 1 << 20,
    VHT               = 1 << 21,
    MORE_IT_PRESENT   = 1 << 31,

    COMMON_A          = TSFT.bits
                      | FLAGS.bits
                      | RATE.bits
                      | CHANNEL.bits
                      | ANTENNA_SIGNAL.bits
                      | ANTENNA_NOISE.bits
                      | ANTENNA.bits,

    COMMON_B          = TSFT.bits
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

bitflags!(Flags: u8 {
    DuringCFP     = 0x01,
    ShortPreamble = 0x02,
    EncryptWep    = 0x04,
    Fragmentation = 0x08,
    IncludesFCS   = 0x10,
    HasPadding    = 0x20,
    FailedFCSChk  = 0x40,
    ShortGuard    = 0x80
})

pub struct Rate {
    pub in_500kbps: u8
}

bitflags!(ChannelFlags: u16 {
    Turbo       = 0x0010,
    CCK         = 0x0020,
    OFDM        = 0x0040,
    Ghz2        = 0x0080,
    Ghz5        = 0x0100,
    PsvScan     = 0x0200,
    DynCCK_OFDM = 0x0400,
    GFSK        = 0x0800
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
