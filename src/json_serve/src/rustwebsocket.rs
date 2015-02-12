use std::old_io::{Stream,BufferedStream,IoResult};
use std::num::{FromPrimitive};

use rustc_serialize::base64::{ToBase64, STANDARD};

use openssl::crypto::hash::{self, Type};

const CONNECTION_FIELD: &'static str = "Connection";
const UPGRADE: &'static str = "upgrade";
const UPGRADE_FIELD: &'static str = "Upgrade";
const WEBSOCKET: &'static str = "websocket";
const HOST_FIELD: &'static str = "Host";
const ORIGIN_FIELD: &'static str = "Origin";
const KEY_FIELD: &'static str = "Sec-WebSocket-Key";
const PROTOCOL_FIELD: &'static str = "Sec-WebSocket-Protocol";
const VERSION_FIELD: &'static str = "Sec-WebSocket-Version";
const VERSION: &'static str = "13";
const ACCEPT_FIELD: &'static str = "Sec-WebSocket-Accept";
const SECRET: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(FromPrimitive)]
pub enum FrameType {
    Empty = 0xF0,
    Error = 0xF1,
    Incomplete = 0xF2,
    Text = 0x01,
    Binary = 0x02,
    Ping = 0x09,
    Pong = 0x0A,
    Opening = 0xF3,
    Closing = 0x08
}

enum State {
    Opening,
    Normal,
    Closing
}

struct Handshake {
    key: String,
    resource: String,
    frame_type: FrameType
}

impl Handshake {
    pub fn get_answer(&self) -> String {
        let res = hash::hash(Type::SHA1, self.key.as_bytes());
        let response_key = res.to_base64(STANDARD);
        format!("HTTP/1.1 101 Switching Protocols\r\n\
                 {}: {}\r\n\
                 {}: {}\r\n\
                 {}: {}\r\n\r\n",
                UPGRADE_FIELD, WEBSOCKET,
                CONNECTION_FIELD, UPGRADE_FIELD,
                ACCEPT_FIELD, response_key)
    }
}

pub fn parse_handshake<S: Stream>(s: &mut BufferedStream<S>) -> Option<Handshake> {
    let line = match s.read_line() {
        Ok(ln) => ln,
        _ => return None
    };

    let prop: Vec<_> = line.split_str(" ").collect();
    let mut hs = Handshake {
        //host: ~"",
        //origin: ~"",
        key: "".to_string(),
        resource: prop[1].trim().to_string(),
        frame_type: FrameType::Opening
    };

    let mut has_handshake = false;
    loop {
        let line = match s.read_line() {
            Ok(ln) => ln,
            _ => return if has_handshake { Some(hs) } else { None }
        };

        let line = line.trim();
        if line.is_empty() {
            return if has_handshake { Some(hs) } else { None };
        }

        let prop: Vec<_> = line.split_str(": ").collect();
        if prop.len() != 2 {
            println!("Unexpected line: '{}'", line);
            return None;
        }
        let key = prop[0].trim();
        let val = prop[1].trim();

        match key {
            KEY_FIELD => {
                hs.key = val.to_string();
                hs.key.push_str(SECRET);
                has_handshake = true;
            }
            _ => () //do nothing
        }
    }
}

static SMALL_FRAME: usize = 125;
static MED_FRAME: usize = 65535;

static MED_FRAME_FLAG: u8 = 126;
static LARGE_FRAME_FLAG: u8 = 127;

pub fn write_frame<W:Writer>(data: &[u8], frame_type: FrameType, w: &mut W) -> IoResult<()> {
    try!(w.write_u8((0x80 | frame_type as u32) as u8));

    if data.len() <= SMALL_FRAME {
        try!(w.write_u8(data.len() as u8));
    } else if data.len() <= MED_FRAME {
        try!(w.write_u8(MED_FRAME_FLAG));
        try!(w.write_be_u16(data.len() as u16));
    } else {
        try!(w.write_u8(LARGE_FRAME_FLAG));
        try!(w.write_be_u64(data.len() as u64));
    }
    try!(w.write_all(data));
    w.flush()
}

pub fn parse_input_frame<S: Stream>(s: &mut BufferedStream<S>) -> (Option<Vec<u8>>, FrameType) {
    let hdr = match s.read_exact(2 as usize) {
        Ok(h) => if h.len() == 2 { h } else { return (None, FrameType::Error) },
        //Ok(h) if h.len() == 2 => h //Fails w/ cannot bind by-move into a pattern guard
        //Ok(ref h) if h.len() == 2 => h.clone(),
        _ => return (None, FrameType::Error)
    };

    if hdr[0] & 0x70 != 0x0    //extensions must be off
    || hdr[0] & 0x80 != 0x80   //no continuation frames
    || hdr[1] & 0x80 != 0x80 { //masking bit must be set
        return (None, FrameType::Error);
    }

    let opcode = (hdr[0] & 0x0F) as u8;
    if let Some(frame_type) = FromPrimitive::from_u8(opcode) {
        let payload_len = hdr[1] & 0x7F;
        if payload_len < 0x7E { //Only handle short payloads right now.
            let toread = (payload_len + 4) as usize; //+4 for mask
            let masked_payload = match s.read_exact(toread) {
                Ok(mp) => mp,
                _ => return (None, FrameType::Error)
            };
            let payload = masked_payload[4..].iter()
                .enumerate()
                .map(|(i, t)| { *t ^ masked_payload[i%4] })
                .collect();
            return (Some(payload), frame_type);
        }

        return (None, frame_type);
    }

    return (None, FrameType::Error);
}
