extern mod std;
extern mod extra;
extern mod crypto;

use std::{io,str,vec};
use std::hashmap::HashMap;
use std::io::Reader;

use extra::base64::{ToBase64, STANDARD};

use crypto::hash;

static CONNECTION_FIELD: &'static str = "Connection";
static UPGRADE: &'static str = "upgrade";
static UPGRADE_FIELD: &'static str = "Upgrade";
static WEBSOCKET: &'static str = "websocket";
static HOST_FIELD: &'static str = "Host";
static ORIGIN_FIELD: &'static str = "Origin";
static KEY_FIELD: &'static str = "Sec-WebSocket-Key";
static PROTOCOL_FIELD: &'static str = "Sec-WebSocket-Protocol";
static VERSION_FIELD: &'static str = "Sec-WebSocket-Version";
static VERSION: &'static str = "13";
static ACCEPT_FIELD: &'static str = "Sec-WebSocket-Accept";
static SECRET: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub enum WSFrameType {
    WS_EMPTY_FRAME = 0xF0,
    WS_ERROR_FRAME = 0xF1,
    WS_INCOMPLETE_FRAME = 0xF2,
    WS_TEXT_FRAME = 0x01,
    WS_BINARY_FRAME = 0x02,
    WS_PING_FRAME = 0x09,
    WS_PONG_FRAME = 0x0A,
    WS_OPENING_FRAME = 0xF3,
    WS_CLOSING_FRAME = 0x08
}

enum WSState {
    WS_STATE_OPENING,
    WS_STATE_NORMAL,
    WS_STATE_CLOSING
}

struct Handshake {
    //host: ~str,
    //origin: ~str,
    key: ~str,
    resource: ~str,
    frameType: WSFrameType
}

impl Handshake {
    pub fn getAnswer(&self) -> ~str {
        let s = self.key + SECRET;
        let res = hash::hash(hash::SHA1, s.as_bytes());
        let responseKey = res.to_base64(STANDARD);
        format!("HTTP/1.1 101 Switching Protocols\r\n\
                 {}: {}\r\n\
                 {}: {}\r\n\
                 {}: {}\r\n\r\n",
                UPGRADE_FIELD, WEBSOCKET,
                CONNECTION_FIELD, UPGRADE_FIELD,
                ACCEPT_FIELD, responseKey)
    }
}

type HeaderFns = HashMap<~str, 'static |&mut Handshake, &str|->()>;

fn headerfns() -> HeaderFns {
    let mut hdrFns = HashMap::new();
    hdrFns.insert(KEY_FIELD.to_owned(), |h: &mut Handshake, v: &str| h.key = v.to_owned());
    //hdrFns.insert(KEY_FIELD, |h: &mut Handshake, v: &str| h.key = v.to_owned());
    hdrFns
}

fn read_line<T: io::Reader>(rdr: &mut T) -> ~str {
    let mut bytes = ~[];
    loop {
        match rdr.read_byte() {
            Some(ch) => {
                if ch == -1 || ch == '\n' as u8 {
                    break;
                }
                bytes.push(ch as u8);
            }
            None => break
        }
    }
    str::from_utf8(bytes).to_owned()
}

pub fn wsParseHandshake<T: io::Reader>(rdr: &mut T) -> Option<Handshake> {
    let hdrFns = headerfns();
    let line = read_line(rdr);
    let prop: ~[~str] = line.split_str(" ").map(|s|s.to_owned()).collect();
    let resource = prop[1].trim();
    let mut hs = Handshake {
        //host: ~"",
        //origin: ~"",
        key: ~"",
        resource: resource.to_owned(),
        frameType: WS_OPENING_FRAME
    };

    let mut hasHandshake = false;
    loop {
        let line = read_line(rdr);
        let line = line.trim();
        if line.is_empty() {
            return if hasHandshake { Some(hs) } else { None };
        }
        let prop: ~[~str] = line.split_str(": ").map(|s|s.to_owned()).collect();
        if prop.len() != 2 {
            println!("Unexpected line: '{}'", line);
            return None;
        }
        let key = prop[0].clone();
        let val = prop[1].trim();
        match hdrFns.find(&key) {
            Some(f) => {
                (*f)(&mut hs, val);
                hasHandshake = true;
            }
            None => () //do nothing
        }
    }
}

static SMALL_FRAME: uint = 125;
static MED_FRAME: uint = 65535;

static MED_FRAME_FLAG: u8 = 126;
static LARGE_FRAME_FLAG: u8 = 127;

pub fn wsMakeFrame(data: &[u8], frameType: WSFrameType) -> ~[u8] {
    let mut out = vec::with_capacity(data.len());
    out.push((0x80 | frameType as int) as u8);

    if data.len() <= SMALL_FRAME {
        out.push(data.len() as u8);
    } else if data.len() <= MED_FRAME {
        out.push(MED_FRAME_FLAG);
        (data.len() as u16).iter_bytes(false, |bytes| {
            out.push_all(bytes); true
        });
    } else {
        out.push(LARGE_FRAME_FLAG);
        (data.len() as u64).iter_bytes(false, |bytes| {
            out.push_all(bytes); true
        });
    }
    out.push_all(data);
    out
}

fn frameTypeFrom(i: u8) -> WSFrameType {
    unsafe { std::cast::transmute(i) }
}

pub fn wsParseInputFrame<T: io::Reader>(rdr: &mut T) -> (Option<~[u8]>, WSFrameType) {
    //io::println("reading header");
    let hdr = rdr.read_bytes(2 as uint);
    if hdr.len() != 2 {
        return (None, WS_ERROR_FRAME);
    }

    if hdr[0] & 0x70 != 0x0    //extensions must be off
    || hdr[0] & 0x80 != 0x80   //no continuation frames
    || hdr[1] & 0x80 != 0x80 { //masking bit must be set
        return (None, WS_ERROR_FRAME);
    }

    let opcode = (hdr[0] & 0x0F) as u8;
    if opcode == WS_TEXT_FRAME as u8
    || opcode == WS_BINARY_FRAME as u8
    || opcode == WS_CLOSING_FRAME as u8
    || opcode == WS_PING_FRAME as u8
    || opcode == WS_PONG_FRAME as u8 {
        let frameType = frameTypeFrom(opcode);
        let payloadLength = hdr[1] & 0x7F;
        if payloadLength < 0x7E { //Only handle short payloads right now.
            let toread = (payloadLength + 4) as uint; //+4 for mask
            let masked_payload = rdr.read_bytes(toread);
            let payload = masked_payload.tailn(4).iter()
                .enumerate()
                .map(|(i, t)| { t ^ masked_payload[i%4] })
                .collect();
            return (Some(payload), frameType);
        }

        return (None, frameType);
    }

    return (None, WS_ERROR_FRAME);
}
