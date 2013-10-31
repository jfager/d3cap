#[feature(globs, macro_rules)];

extern mod std;
extern mod extra;
extern mod crypto;

use std::{cast,os,ptr,rt,str,task};
use std::hashmap::HashMap;
use std::comm::SharedChan;
use std::task::TaskBuilder;
use std::cell::Cell;
use std::libc::c_char;

use std::rt::io::{io_error,Acceptor,Listener,Reader,Writer};
use std::rt::io::net::tcp::TcpListener;
use std::rt::io::net::ip::{Ipv4Addr,SocketAddr};

use extra::{json,time};
use extra::json::ToJson;
use extra::treemap::TreeMap;

use rustpcap::*;
use rustwebsocket::*;
use ring::RingBuffer;

mod rustpcap;
mod ring;
mod rustwebsocket;

type Addrs<T> = (T, T);

#[deriving(Eq, IterBytes)]
struct OrdAddrs<T>(Addrs<T>);
impl <T: Ord+IterBytes> OrdAddrs<T> {
    fn from(a: T, b: T) -> OrdAddrs<T> {
        if a <= b { OrdAddrs((a, b)) } else { OrdAddrs((b, a)) }
    }
}

type AddrChanMap<T> = HashMap<~OrdAddrs<T>, ~Chan<~PktMeta<T>>>;

struct ProtocolHandler<T> {
    typ: &'static str,
    count: u64,
    size: u64,
    ch: MulticastSharedChan<~str>,
    routes: HashMap<~OrdAddrs<T>, ~RouteStats<T>>
}

impl <T: Ord+IterBytes+Eq+Clone+Send+ToStr> ProtocolHandler<T> {
    fn new(typ: &'static str, ch: MulticastSharedChan<~str>) -> ProtocolHandler<T> {
        ProtocolHandler { typ: typ, count: 0, size: 0, ch: ch, routes: HashMap::new() }
    }
    fn update(&mut self, pkt: ~PktMeta<T>) {
        let key = ~OrdAddrs::from(pkt.src.clone(), pkt.dst.clone());
        let stats = self.routes.find_or_insert_with(key, |k| {
            ~RouteStats::new(self.typ, k.first(), k.second())
        });
        stats.update(pkt);
        let msg = route_msg(self.typ, *stats);
        self.ch.send(msg);
    }
    fn spawn(typ: &'static str, ch: &MulticastSharedChan<~str>) -> Chan<~PktMeta<T>> {
        let (port, chan) = stream();
        do task::spawn_with(ch.clone()) |oc| {
            let mut handler = ProtocolHandler::new(typ, oc);
            loop {
                let pkt: ~PktMeta<T> = port.recv();
                handler.update(pkt);
            }
        }
        chan
    }
}

fn route_msg<T:ToStr>(typ: &str, rt: &RouteStats<T>) -> ~str {
    let mut m = ~TreeMap::new();
    m.insert(~"type", typ.to_str().to_json());
    m.insert(~"a", rt.a.addr.to_str().to_json());
    m.insert(~"from_a_count", rt.a.sent_count.to_json());
    m.insert(~"from_a_size", rt.a.sent_size.to_json());
    m.insert(~"b", rt.b.addr.to_str().to_json());
    m.insert(~"from_b_count", rt.b.sent_count.to_json());
    m.insert(~"from_b_size", rt.b.sent_size.to_json());
    json::Object(m).to_str()
}

struct AddrStats<T> {
    addr: T,
    sent_count: u64,
    sent_size: u64,
}
impl<T> AddrStats<T> {
    fn new(addr:T) -> AddrStats<T> {
        AddrStats { addr: addr, sent_count: 0, sent_size: 0 }
    }
    fn update(&mut self, size: u32) {
        self.sent_count += 1;
        self.sent_size += size as u64;
    }
}

struct RouteStats<T> {
    typ: &'static str,
    a: AddrStats<T>,
    b: AddrStats<T>,
    last: RingBuffer<~PktMeta<T>>
}

impl <T: IterBytes+Eq+Clone+Send+ToStr> RouteStats<T> {
    fn new(typ: &'static str, a: T, b: T) -> RouteStats<T> {
        RouteStats {
            typ: typ,
            a: AddrStats::new(a),
            b: AddrStats::new(b),
            last: RingBuffer::new(5),
        }
    }
    fn update(&mut self, pkt: ~PktMeta<T>) {
        if pkt.src == self.a.addr {
            self.a.update(pkt.size);
        } else {
            self.b.update(pkt.size);
        }
    }
}

struct PktMeta<T> {
    src: T,
    dst: T,
    size: u32,
    time: time::Timespec
}
impl<T> PktMeta<T> {
    fn new(src: T, dst: T, size: u32) -> PktMeta<T> {
        let t = time::get_time();
        PktMeta { src: src, dst: dst, size: size, time: t }
    }
}
impl <T:Clone> PktMeta<T> {
    fn addrs(&self) -> Addrs<T> {
        (self.src.clone(), self.dst.clone())
    }
}

struct ProtocolHandlers {
    mac: Chan<~PktMeta<MacAddr>>,
    ip4: Chan<~PktMeta<IP4Addr>>,
    ip6: Chan<~PktMeta<IP6Addr>>
}

struct Packet {
    header: *pcap_pkthdr,
    packet: *u8
}
impl Packet {
    fn parse(&self, ctx: &mut ProtocolHandlers) {
        unsafe {
            let hdr = *self.header;
            if hdr.caplen < hdr.len {
                println!("WARN: Capd only [{}] bytes of packet with length [{}]",
                         hdr.caplen, hdr.len);
            }
            if hdr.len > ETHERNET_HEADER_BYTES as u32 {
                let ehp: *EthernetHeader = cast::transmute(self.packet);
                (*ehp).parse(ctx, hdr.len);
                (*ehp).dispatch(self, ctx);
            }
        }
    }
}

macro_rules! fixed_vec_iter_bytes(
    ($t:ty) => (
        impl IterBytes for $t {
            fn iter_bytes(&self, lsb0: bool, f: std::to_bytes::Cb) -> bool {
                self.as_slice().iter_bytes(lsb0, f)
            }
        }
    );
)

macro_rules! fixed_vec_eq(
    ($t:ty) => (
        impl Eq for $t {
            fn eq(&self, other: &$t) -> bool {
                self.as_slice().eq(&other.as_slice())
            }
        }
    );
)

macro_rules! fixed_vec_ord(
    ($t:ty) => (
        impl Ord for $t {
            fn lt(&self, other: &$t) -> bool {
                self.as_slice().lt(&other.as_slice())
            }
        }
    );
)

macro_rules! fixed_vec_clone(
    ($t:ident, $arrt: ty, $len:expr) => (
        impl Clone for $t {
            fn clone(&self) -> $t {
                let mut new_vec: [$arrt, ..$len] = [0, .. $len];
                for (x,y) in new_vec.mut_iter().zip((**self).iter()) {
                    *x = y.clone();
                }
                $t(new_vec)
            }
        }
    );
)

static ETHERNET_MAC_ADDR_BYTES: int = 6;
static ETHERNET_ETHERTYPE_BYTES: int = 2;
static ETHERNET_HEADER_BYTES: int =
    (ETHERNET_MAC_ADDR_BYTES * 2) + ETHERNET_ETHERTYPE_BYTES;

struct MacAddr([u8,..ETHERNET_MAC_ADDR_BYTES]);

impl ToStr for MacAddr {
    fn to_str(&self) -> ~str {
        let f = |x: u8,y| x.to_str_radix(y);
        return format!("{}:{}:{}:{}:{}:{}",
                       f(self[0], 16), f(self[1], 16), f(self[2], 16),
                       f(self[3], 16), f(self[4], 16), f(self[5], 16)
                      );
    }
}

fixed_vec_iter_bytes!(MacAddr)
fixed_vec_eq!(MacAddr)
fixed_vec_ord!(MacAddr)
fixed_vec_clone!(MacAddr, u8, ETHERNET_MAC_ADDR_BYTES)

struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    typ: u16
}
impl EthernetHeader {
    fn parse(&self, ctx: &mut ProtocolHandlers, size: u32) {
        ctx.mac.send(~PktMeta::new(self.src, self.dst, size));
    }
}

impl EthernetHeader {
    fn dispatch(&self, p: &Packet, ctx: &mut ProtocolHandlers) {
        match self.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => unsafe {
                let ipp: *IP4Header = transmute_offset(p.packet, ETHERNET_HEADER_BYTES);
                (*ipp).parse(ctx, (*p.header).len);
            },
            ETHERTYPE_IP6 => unsafe {
                let ipp: *IP6Header = transmute_offset(p.packet, ETHERNET_HEADER_BYTES);
                (*ipp).parse(ctx, (*p.header).len);
            },
            ETHERTYPE_802_1X => {
                //io::println("802.1X!");
            },
            x => {
                println!("Unknown type: {}", x.to_str_radix(16));
            }
        }
    }
}


static ETHERTYPE_ARP: u16 = 0x0608;
static ETHERTYPE_IP4: u16 = 0x0008;
static ETHERTYPE_IP6: u16 = 0xDD86;
static ETHERTYPE_802_1X: u16 = 0x8E88;

struct IP4Addr([u8,..4]);
impl ToStr for IP4Addr {
    fn to_str(&self) -> ~str {
        format!("{}.{}.{}.{}",
                self[0] as uint, self[1] as uint, self[2] as uint, self[3] as uint)
    }
}

fixed_vec_iter_bytes!(IP4Addr)
fixed_vec_eq!(IP4Addr)
fixed_vec_ord!(IP4Addr)
fixed_vec_clone!(IP4Addr, u8, 4)

struct IP4Header {
    ver_ihl: u8,
    dscp_ecn: u8,
    len: u16,
    ident: u16,
    flags_frag: u16,
    ttl: u8,
    proto: u8,
    hchk: u16,
    src: IP4Addr,
    dst: IP4Addr,
}

impl IP4Header {
    fn parse(&self, ctx: &mut ProtocolHandlers, size: u32) {
        ctx.ip4.send(~PktMeta::new(self.src, self.dst, size));
    }
}

struct IP6Addr([u16,..8]);
impl ToStr for IP6Addr {
    fn to_str(&self) -> ~str {
        match (**self) {
            //ip4-compatible
            [0,0,0,0,0,0,g,h] => {
                format!("::{}.{}.{}.{}", (g >> 8) as u8, g as u8,
                        (h >> 8) as u8, h as u8)
            }

            // ip4-mapped address
            [0, 0, 0, 0, 0, 0xFFFF, g, h] => {
                format!("::FFFF:{}.{}.{}.{}", (g >> 8) as u8, g as u8,
                        (h >> 8) as u8, h as u8)
            }

            [a, b, c, d, e, f, g, h] => {
                format!("{}:{}:{}:{}:{}:{}:{}:{}", a, b, c, d, e, f, g, h)
            }
        }
    }
}



fixed_vec_iter_bytes!(IP6Addr)
fixed_vec_eq!(IP6Addr)
fixed_vec_ord!(IP6Addr)
fixed_vec_clone!(IP6Addr, u16, 8)

struct IP6Header {
    ver_tc_fl: u32,
    len: u16,
    nxthdr: u8,
    hoplim: u8,
    src: IP6Addr,
    dst: IP6Addr
}
impl IP6Header {
    fn parse(&self, ctx: &mut ProtocolHandlers, size: u32) {
        ctx.ip6.send(~PktMeta::new(self.src, self.dst, size));
    }
}

unsafe fn transmute_offset<T,U>(base: *T, offset: int) -> U {
    cast::transmute(ptr::offset(base, offset))
}

extern fn handler(args: *u8, header: *pcap_pkthdr, packet: *u8) {
    unsafe {
        let ctx: *mut ProtocolHandlers = cast::transmute(args);
        let p = Packet { header: header, packet: packet };
        p.parse(&mut *ctx);
    }
}

fn websocketWorker<T: rt::io::Reader+rt::io::Writer>(tcps: &mut T, data_po: &Port<~str>) {
    println!("websocketWorker");
    let handshake = wsParseHandshake(tcps);
    match handshake {
        Some(hs) => {
            let rsp = hs.getAnswer();
            tcps.write(rsp.as_bytes());
        }
        None => tcps.write("HTTP/1.1 404 Not Found\r\n\r\n".as_bytes())
    }

    do io_error::cond.trap(|_| ()).inside {
        loop {
            let mut counter = 0;
            while data_po.peek() && counter < 100 {
                let msg = data_po.recv();
                tcps.write(wsMakeFrame(msg.as_bytes(), WS_TEXT_FRAME));
                counter += 1;
            }
            let (_, frameType) = wsParseInputFrame(tcps);
            match frameType {
                WS_CLOSING_FRAME |
                WS_ERROR_FRAME   => {
                    tcps.write(wsMakeFrame([], WS_CLOSING_FRAME));
                    break;
                }
                _ => ()
            }
        }
    }
    println!("Done with worker");
}

fn uiServer(mc: Multicast<~str>, port: u16) {
    let addr = SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: port };
    let listener = TcpListener::bind(addr);
    let mut acceptor = listener.listen();
    println!("Server listening on port {}", port as uint);

    let mut workercount = 0;
    for s in acceptor.incoming() {
        let tcp_stream = Cell::new(s);
        let (conn_po, conn_ch) = stream();
        mc.push(|msg| { conn_ch.send(msg.to_owned()); });
        do named_task(format!("websocketWorker_{}", workercount)).spawn {
            let mut tcp_stream = tcp_stream.take();
            websocketWorker(&mut tcp_stream, &conn_po);
        }
        workercount += 1;
    }
}

enum MulticastMsg<T> {
    Msg(T),
    MsgCb(~fn(&T))
}
struct Multicast<T> {
    priv ch: SharedChan<MulticastMsg<T>>,
}
impl<T:Send+Clone> Multicast<T> {
    fn new() -> Multicast<T> {
        let (po, ch) = stream::<MulticastMsg<T>>();
        do spawn {
            let mut cbs: ~[~fn(&T)] = ~[];
            loop {
                match po.try_recv() {
                    Some(Msg(msg)) => {
                        for cb in cbs.iter() {
                            (*cb)(&msg);
                        }
                    }
                    Some(MsgCb(cb)) => {
                        cbs.push(cb);
                    }
                    None => break
                }
            }
        }
        Multicast { ch: SharedChan::new(ch) }
    }

    fn get_chan(&self) -> MulticastSharedChan<T> {
        MulticastSharedChan { ch: self.ch.clone() }
    }

    fn push(&self, cb: ~fn(&T)) {
        self.ch.send(MsgCb(cb));
    }
}

struct MulticastSharedChan<T> {
    priv ch: SharedChan<MulticastMsg<T>>
}
impl<T:Send> MulticastSharedChan<T> {
    fn send(&self, msg: T) {
        self.ch.send(Msg(msg));
    }
}
impl<T:Send> Clone for MulticastSharedChan<T> {
    fn clone(&self) -> MulticastSharedChan<T> {
        MulticastSharedChan { ch: self.ch.clone() }
    }
}

fn find_device(errbuf: &mut [c_char]) -> *c_char {
    let dev = get_device(errbuf);
    match dev {
        Some(d) => {
            unsafe {
                println!("Found device {}", str::raw::from_c_str(d));
            }
            d
        }
        None => fail!("No device available")
    }
}

#[fixed_stack_segment]
fn capture(data_ch: &MulticastSharedChan<~str>, dev: *c_char, errbuf: &mut [c_char]) {

    let ctx = ~ProtocolHandlers {
        mac: ProtocolHandler::spawn("mac", data_ch),
        ip4: ProtocolHandler::spawn("ip4", data_ch),
        ip6: ProtocolHandler::spawn("ip6", data_ch)
    };

    let session = start_session(dev, errbuf);
    match session {
        Some(s) => unsafe {
            println!("Starting pcap_loop");
            pcap_loop(s, -1, handler, cast::transmute(ptr::to_unsafe_ptr(ctx)));
        },
        None => unsafe {
            println!("Couldn't open device {}: {:?}\n",
                     str::raw::from_c_str(dev),
                     errbuf);
        }
    }
}

pub fn named_task(name: ~str) -> TaskBuilder {
    let mut ui_task = task::task();
    ui_task.name(name);
    ui_task
}

fn main() {
    use extra::getopts::*;

    let PORT_OPT = "p";
    let INTERFACE_OPT = "i";

    let args = os::args();
    let opts = ~[
        optopt(PORT_OPT),
        optopt(INTERFACE_OPT)
    ];

    let matches = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()) }
    };

    let port = matches.opt_str(PORT_OPT).unwrap_or(~"7432");
    let port = from_str::<u16>(port).unwrap();

    let mc = Multicast::new();
    let data_ch = mc.get_chan();

    do named_task(~"socket_listener").spawn_with(mc) |mc| {
        uiServer(mc, port);
    }

    do named_task(~"packet_capture").spawn_with(data_ch) |ch| {
        let mut errbuf = std::vec::with_capacity(256);
        let dev = matches.opt_str(INTERFACE_OPT);
        let dev = match dev {
            Some(d) => unsafe { d.to_c_str().unwrap() },
            None => find_device(errbuf)
        };
        capture(&ch, dev, errbuf);
    }
}