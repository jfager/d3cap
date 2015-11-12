#![allow(dead_code)]

use std::mem::size_of;

use util::skip_cast;

//For possible reference:
//https://github.com/simsong/tcpflow/blob/master/src/wifipcap/ieee802_11_radio.h

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct RadiotapHeader {
    pub it_version: u8, // 8 -> 1
    pub it_pad: u8, // 8 -> 1
    pub it_len: u16, // 16 -> 2
    pub it_present: ItPresent // 32 -> 4
}
//size_of should == 8

bitflags!(flags ItPresent: u32 {
    const TSFT              = 1,
    const FLAGS             = 1 << 1,
    const RATE              = 1 << 2,
    const CHANNEL           = 1 << 3,
    const FHSS              = 1 << 4,
    const ANTENNA_SIGNAL    = 1 << 5,
    const ANTENNA_NOISE     = 1 << 6,
    const LOCK_QUALITY      = 1 << 7,
    const TX_ATTENUATION    = 1 << 8,
    const DB_TX_ATTENUATION = 1 << 9,
    const DBM_TX_POWER      = 1 << 10,
    const ANTENNA           = 1 << 11,
    const DB_ANTENNA_SIGNAL = 1 << 12,
    const DB_ANTENNA_NOISE  = 1 << 13,
    const RX_FLAGS          = 1 << 14,
    const TX_FLAGS          = 1 << 15,
    const RTS_RETRIES       = 1 << 16,
    const DATA_RETRIES      = 1 << 17,
    const MCS               = 1 << 19,
    const A_MPDU_STATUS     = 1 << 20,
    const VHT               = 1 << 21,
    const MORE_IT_PRESENT   = 1 << 31,

    const COMMON_A          = TSFT.bits
                            | FLAGS.bits
                            | RATE.bits
                            | CHANNEL.bits
                            | ANTENNA_SIGNAL.bits
                            | ANTENNA_NOISE.bits
                            | ANTENNA.bits,

    const COMMON_B          = TSFT.bits
                            | FLAGS.bits
                            | CHANNEL.bits
                            | ANTENNA_SIGNAL.bits
                            | ANTENNA_NOISE.bits
                            | ANTENNA.bits
                            | MCS.bits
});

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct Tsft {
    pub timer_micros: u64
}

bitflags!(flags Flags: u8 {
    const DURING_CFP     = 0x01,
    const SHORT_PREAMBLE = 0x02,
    const ENCRYPT_WEP    = 0x04,
    const FRAGMENTATION  = 0x08,
    const INCLUDES_FCS   = 0x10,
    const HAS_PADDING    = 0x20,
    const FAILED_FCS_CHK = 0x40,
    const SHORT_GUARD    = 0x80
});

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct Rate {
    pub in_500kbps: u8
}

bitflags!(flags ChannelFlags: u16 {
    const TURBO        = 0x0010,
    const CCK          = 0x0020,
    const OFDM         = 0x0040,
    const GHZ_2        = 0x0080,
    const GHZ_5        = 0x0100,
    const PSV_SCAN     = 0x0200,
    const DYN_CCK_OFDM = 0x0400,
    const GFSK         = 0x0800
});


#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct Channel {
    pub mhz: u16,
    pub flags: ChannelFlags
}

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct AntennaSignal {
    pub dbm: i8
}

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct AntennaNoise {
    pub dbm: i8
}

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct Antenna {
    pub idx: u8
}

#[derive(Copy,Clone,Debug)]
#[repr(packed)]
pub struct Mcs {
    pub known: u8,
    pub flags: u8,
    pub mcs: u8
}

// For now just predefining a few types of packets I actually see with my setup,
// rather than defining a general parser.
#[derive(Copy,Clone)]
#[repr(packed)]
pub struct CommonA {
    pub tsft: Tsft,  // 8
    pub flags: Flags, // 1
    pub rate: Rate, // 1
    pub channel: Channel, // 2 + 2 = 4
    pub antenna_signal: AntennaSignal, // 1
    pub antenna_noise: AntennaNoise, // 1
    pub antenna: Antenna // 1
}
// sizeof should be 17.

impl CommonA {
    pub fn parse(hdr: &RadiotapHeader) -> Option<&CommonA> {
        let sz = size_of::<RadiotapHeader>() + size_of::<CommonA>();
        if hdr.it_present == COMMON_A
        && hdr.it_len as usize >= sz {
            let out: &CommonA = unsafe { skip_cast(hdr) };
            Some(out)
        } else {
            None
        }
    }
}

#[repr(packed)]
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
    pub fn parse(hdr: &RadiotapHeader) -> Option<&CommonB> {
        let sz = size_of::<RadiotapHeader>() + size_of::<CommonB>();
        if hdr.it_present == COMMON_B
        && hdr.it_len as usize >= sz {
            let out: &CommonB = unsafe { skip_cast(hdr) };
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
