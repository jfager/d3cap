use std::io::{self,Read,Write,BufRead,BufStream};

use rustc_serialize::base64::{ToBase64, STANDARD};
use byteorder::{BigEndian, WriteBytesExt};

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

fn from_prim(prim: u8) -> Option<FrameType> {
   use self::FrameType::*;
   match prim {
      0xF0 => Some(Empty),
      0xF1 => Some(Error),
      0xF2 => Some(Incomplete),
      0x01 => Some(Text),
      0x02 => Some(Binary),
      0x09 => Some(Ping),
      0x0A => Some(Pong),
      0xF3 => Some(Opening),
      0x0  => Some(Closing),
      _    => None
    }
}

enum State {
    Opening,
    Normal,
    Closing
}

pub struct Handshake {
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

pub fn parse_handshake<S: Read+Write>(s: &mut BufStream<S>) -> Option<Handshake> {
    let mut line = String::new();
    if s.read_line(&mut line).is_err() {
        return None
    };

    let prop: Vec<_> = line.split(" ").collect();
    let mut hs = Handshake {
        //host: ~"",
        //origin: ~"",
        key: "".to_string(),
        resource: prop[1].trim().to_string(),
        frame_type: FrameType::Opening
    };

    let mut has_handshake = false;
    loop {
        let mut line = String::new();
        if s.read_line(&mut line).is_err() {
            return if has_handshake { Some(hs) } else { None }
        };

        let line = line.trim();
        if line.is_empty() {
            return if has_handshake { Some(hs) } else { None };
        }

        let prop: Vec<_> = line.split(": ").collect();
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

pub fn write_frame<W:Write>(data: &[u8], frame_type: FrameType, w: &mut W) -> io::Result<()> {
    try!(w.write_u8((0x80 | frame_type as u32) as u8));

    if data.len() <= SMALL_FRAME {
        try!(w.write_u8(data.len() as u8));
    } else if data.len() <= MED_FRAME {
        try!(w.write_u8(MED_FRAME_FLAG));
        try!(w.write_u16::<BigEndian>(data.len() as u16));
    } else {
        try!(w.write_u8(LARGE_FRAME_FLAG));
        try!(w.write_u64::<BigEndian>(data.len() as u64));
    }
    try!(w.write_all(data));
    w.flush()
}

pub fn parse_input_frame<S: Read+Write>(s: &mut BufStream<S>) -> (Option<Vec<u8>>, FrameType) {
    let mut hdr = [0; 2];
    match s.read(&mut hdr) {
        Ok(sz) => if sz != 2 { return (None, FrameType::Error) },
        _ => return (None, FrameType::Error)
    };

    if hdr[0] & 0x70 != 0x0    //extensions must be off
    || hdr[0] & 0x80 != 0x80   //no continuation frames
    || hdr[1] & 0x80 != 0x80 { //masking bit must be set
        return (None, FrameType::Error);
    }

    let opcode = hdr[0] & 0x0F;
    if let Some(frame_type) = from_prim(opcode) {
        let payload_len = hdr[1] & 0x7F;
        if payload_len < 0x7E { //Only handle short payloads right now.
            let toread = (payload_len + 4) as usize; //+4 for mask
            let mut masked_payload = vec![0; toread];
            match s.read(&mut masked_payload) {
                Ok(sz) => if sz != toread { return (None, FrameType::Error) },
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
