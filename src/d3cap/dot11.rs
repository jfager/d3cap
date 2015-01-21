#![allow(dead_code)]

use ether::{MacAddr};
use std::fmt::{Show, Formatter, Error};

// For possible reference:
// https://github.com/simsong/tcpflow/blob/master/src/wifipcap/wifipcap.h
// For definitive reference:
// http://standards.ieee.org/getieee802/download/802.11-2012.pdf

bitflags!(flags FrameControlFlags: u8 {
    const TO_DS           = 1 << 0,
    const FROM_DS         = 1 << 1,
    const MORE_FRAGS      = 1 << 2,
    const RETRY           = 1 << 3,
    const POWER_MGMT      = 1 << 4,
    const MORE_DATA       = 1 << 5,
    const PROTECTED_FRAME = 1 << 6,
    const ORDER           = 1 << 7
});

impl Show for FrameControlFlags {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.write_str(format!("{:?}", self.bits).as_slice())
    }
}

#[derive(Show)]
#[repr(packed)]
pub struct FrameControl {
    pub ty: u8,
    pub flags: FrameControlFlags
}

impl FrameControl {
    /// When this is non-zero, the packet is bogus; however, being 0 is not sufficient
    /// to imply that the packet is good.  From verifying with Wireshark and reading
    /// around, bogus packets can be pretty common (and are on my network and card), so
    /// you need to be able to handle them.
    pub fn protocol_version(&self) -> u8 {
        self.ty & 0b00000011
    }
    pub fn frame_type(&self) -> FrameType {
        match (self.ty & 0b00001100) >> 2 {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            _ => FrameType::Unknown
        }
    }
    pub fn frame_subtype(&self) -> u8 {
        (self.ty & 0b11110000) >> 4
    }
    pub fn has_flag(&self, flag: FrameControlFlags) -> bool {
        self.flags.contains(flag)
    }
}


#[derive(Show)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Unknown
}

//8.2.4.2 Duration/ID field
#[derive(Show)]
#[repr(packed)]
pub struct DurationID {
    dur_id: u16
}

#[derive(Show)]
#[repr(packed)]
pub struct Dot11BaseHeader {
    pub fr_ctrl: FrameControl,
    pub dur_id: DurationID,
}


type FCS = [u8; 4];

// 8.2.4.3.5 DA field
// The DA field contains an IEEE MAC individual or group address that
// identifies the MAC entity or entities intended as the final
// recipient(s) of the MSDU (or fragment thereof) or A-MSDU, as
// defined in 8.3.2.1, contained in the frame body field.

// 8.2.4.3.6 SA field
// The SA field contains an IEEE MAC individual address that
// identifies the MAC entity from which the transfer of the MSDU
// (or fragment thereof) or A-MSDU, as defined in 8.3.2.1, contained
// in the frame body field was initiated. The individual/group bit
// is always transmitted as a 0 in the source address.

// 8.2.4.3.7 RA field
// The RA field contains an IEEE MAC individual or group address that
// identifies the intended immediate recipient STA(s), on the WM, for
// the information contained in the frame body field.

// 8.2.4.3.8 TA field
// The TA field contains an IEEE MAC individual address that
// identifies the STA that has transmitted, onto the WM, the MPDU
// contained in the frame body field. The Individual/Group bit is
// always transmitted as a 0 in the transmitter address.

// Frame types

// 8.3.1 Control Frames

// 8.3.1.2 RTS
#[repr(packed)]
pub struct RTS {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub ta: MacAddr,
    pub fcs: FCS
}

// 8.3.1.3 CTS
#[repr(packed)]
pub struct CTS {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub fcs: FCS
}

// 8.3.1.4 ACK
#[repr(packed)]
pub struct ACK {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub fcs: FCS
}

// 8.3.1.5 PS-Poll
#[repr(packed)]
pub struct PSPoll {
    pub base: Dot11BaseHeader,
    pub bssid: MacAddr, //ra
    pub ta: MacAddr,
    pub fcs: FCS
}

// 8.3.1.6 CF-End
#[repr(packed)]
pub struct CFEnd {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub bssid: MacAddr, //ta
    pub fcs: FCS
}

// 8.3.1.7 CF-End+CF-Ack
#[repr(packed)]
pub struct CFEndCFAck {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub bssid: MacAddr, //ta
    pub fcs: FCS
}

// 8.3.1.8 BlockAckReq
#[repr(packed)]
pub struct BlockAckReq {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub ta: MacAddr,
    pub bar_ctl: [u8; 2]
}

// 8.3.1.9 BlockAck
#[repr(packed)]
pub struct BlockAck {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub ta: MacAddr,
    pub ba_ctl: [u8; 2]
}

// 8.3.1.10 Control Wrapper
#[repr(packed)]
pub struct ControlWrapper {
    pub base: Dot11BaseHeader,
    pub ra: MacAddr,
    pub cf_ctl: [u8; 2],
    pub ht_ctl: [u8; 4]
}

// 8.3.2 Data Frames

// 8.3.2.1 Data Frame Header
#[repr(packed)]
pub struct DataFrameHeader {
    pub base: Dot11BaseHeader,
    pub addr1: MacAddr,
    pub addr2: MacAddr,
    pub addr3: MacAddr,
    pub seq_ctl: [u8; 2]
}

// | To DS | From DS | Address 1  | Address 2  | Address 3      | Address 4     |
// |       |         |            |            | MSDU  | A-MSDU | MSDU | A-MSDU |
// | 0     | 0       | RA = DA    | TA = SA    | BSSID | BSSID  | N/A  | N/A    |
// | 0     | 1       | RA = DA    | TA = BSSID | SA    | BSSID  | N/A  | N/A    |
// | 1     | 0       | RA = BSSID | TA = SA    | DA    | BSSID  | N/A  | N/A    |
// | 1     | 1       | RA         | TA         | DA    | BSSID  | SA   | BSSID  |

impl DataFrameHeader {
    fn get_src(&self) -> MacAddr {
        match (self.base.fr_ctrl.has_flag(TO_DS), self.base.fr_ctrl.has_flag(FROM_DS)) {
            (false, false) => self.addr2,
            (false, true)  => self.addr3,
            (true,  false) => self.addr2,
            (true,  true)  => panic!("can't handle this yet")
        }
    }

    fn get_dest(&self) -> MacAddr {
        match (self.base.fr_ctrl.has_flag(TO_DS), self.base.fr_ctrl.has_flag(FROM_DS)) {
            (false, false) => self.addr1,
            (false, true)  => self.addr1,
            (true,  false) => self.addr3,
            (true,  true)  => self.addr3
        }
    }
}

// 8.3.3 Management Frames

// 8.3.3.1 Management Frame Format
#[repr(packed)]
pub struct ManagementFrameHeader {
    pub base: Dot11BaseHeader,
    pub addr1: MacAddr,
    pub addr2: MacAddr,
    pub addr3: MacAddr,
    pub seq_ctl: [u8; 2],
    pub ht_ctl: [u8; 4]
}
