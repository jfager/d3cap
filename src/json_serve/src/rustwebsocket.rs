use std::io::{Stream,BufferedStream,IoResult};

use rustc_serialize::base64::{ToBase64, STANDARD};

use openssl::crypto::hash::{mod, HashType};

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

#[deriving(FromPrimitive)]
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
        let res = hash::hash(HashType::SHA1, self.key.as_bytes());
        let response_key = res.as_slice().to_base64(STANDARD);
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

    let prop: Vec<&str> = line.as_slice().split_str(" ").collect();
    let mut hs = Handshake {
        //host: ~"",
        //origin: ~"",
        key: "".to_string(),
        resource: prop[1].as_slice().trim().to_string(),
        frame_type: FrameType::Opening
    };

    let mut has_handshake = false;
    loop {
        let line = match s.read_line() {
            Ok(ln) => ln,
            _ => return if has_handshake { Some(hs) } else { None }
        };

        let line = line.as_slice().trim();
        if line.is_empty() {
            return if has_handshake { Some(hs) } else { None };
        }

        let prop: Vec<&str> = line.as_slice().split_str(": ").collect();
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

static SMALL_FRAME: uint = 125;
static MED_FRAME: uint = 65535;

static MED_FRAME_FLAG: u8 = 126;
static LARGE_FRAME_FLAG: u8 = 127;

pub fn write_frame<W:Writer>(data: &[u8], frame_type: FrameType, w: &mut W) -> IoResult<()> {
    try!(w.write_u8((0x80 | frame_type as int) as u8));

    if data.len() <= SMALL_FRAME {
        try!(w.write_u8(data.len() as u8));
    } else if data.len() <= MED_FRAME {
        try!(w.write_u8(MED_FRAME_FLAG));
        try!(w.write_be_u16(data.len() as u16));
    } else {
        try!(w.write_u8(LARGE_FRAME_FLAG));
        try!(w.write_be_u64(data.len() as u64));
    }
    try!(w.write(data));
    w.flush()
}

fn frame_type_from(i: u8) -> FrameType {
    FromPrimitive::from_u8(i).unwrap()
}

pub fn parse_input_frame<S: Stream>(s: &mut BufferedStream<S>) -> (Option<Vec<u8>>, FrameType) {
    let hdr = match s.read_exact(2 as uint) {
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
    if opcode == FrameType::Text as u8
    || opcode == FrameType::Binary as u8
    || opcode == FrameType::Closing as u8
    || opcode == FrameType::Ping as u8
    || opcode == FrameType::Pong as u8 {
        let frame_type = frame_type_from(opcode);
        let payload_len = hdr[1] & 0x7F;
        if payload_len < 0x7E { //Only handle short payloads right now.
            let toread = (payload_len + 4) as uint; //+4 for mask
            let masked_payload = match s.read_exact(toread) {
                Ok(mp) => mp,
                _ => return (None, FrameType::Error)
            };
            let payload = masked_payload.slice_from(4).iter()
                .enumerate()
                .map(|(i, t)| { *t ^ masked_payload[i%4] })
                .collect();
            return (Some(payload), frame_type);
        }

        return (None, frame_type);
    }

    return (None, FrameType::Error);
}
