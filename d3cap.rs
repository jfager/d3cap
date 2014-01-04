#[feature(globs, macro_rules)];

extern mod std;
extern mod extra;
extern mod crypto;

use std::{cast,os,ptr,task};
use std::hashmap::HashMap;

use extra::{json,time};
use extra::json::ToJson;
use extra::treemap::TreeMap;

use rustpcap::*;
use ring::RingBuffer;
use multicast::{Multicast, MulticastChan};
use uiserver::uiServer;
use util::{named_task, transmute_offset};

mod rustpcap;
mod ring;
mod rustwebsocket;
mod multicast;
mod fixed_vec_macros;
mod uiserver;
mod util;

type Addrs<T> = (T, T);

#[deriving(Eq, IterBytes)]
struct OrdAddrs<T>(Addrs<T>);
impl<T: Ord+IterBytes> OrdAddrs<T> {
    fn from(a: T, b: T) -> OrdAddrs<T> {
        if a <= b { OrdAddrs((a, b)) } else { OrdAddrs((b, a)) }
    }
}

struct ProtocolHandler<T, C> {
    typ: &'static str,
    count: u64,
    size: u64,
    ch: MulticastChan<C>,
    routes: HashMap<~OrdAddrs<T>, ~RouteStats<T>>
}

impl<T: Ord+IterBytes+Eq+Clone+Send+ToStr> ProtocolHandler<T,~str> {
    fn new(typ: &'static str, ch: MulticastChan<~str>) -> ProtocolHandler<T,~str> {
        //FIXME:  this is the map that's hitting https://github.com/mozilla/rust/issues/11102
        ProtocolHandler { typ: typ, count: 0, size: 0, ch: ch, routes: HashMap::new() }
    }
    fn update(&mut self, pkt: &PktMeta<T>) {
        let key = ~OrdAddrs::from(pkt.src.clone(), pkt.dst.clone());
        let stats = self.routes.find_or_insert_with(key, |k| {
            ~RouteStats::new(self.typ, k.first(), k.second())
        });
        stats.update(pkt);
        let msg = route_msg(self.typ, *stats);
        self.ch.send(msg);
    }
    fn spawn(typ: &'static str, ch: &MulticastChan<~str>) -> Chan<~PktMeta<T>> {
        let (port, chan) = Chan::new();
        let oc = ch.clone();
        do named_task(format!("{}_handler", typ)).spawn {
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

impl<T: IterBytes+Eq+Clone+Send+ToStr> RouteStats<T> {
    fn new(typ: &'static str, a: T, b: T) -> RouteStats<T> {
        RouteStats {
            typ: typ,
            a: AddrStats::new(a),
            b: AddrStats::new(b),
            last: RingBuffer::new(5),
        }
    }
    fn update(&mut self, pkt: &PktMeta<T>) {
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
impl<T:Clone> PktMeta<T> {
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
        let hdr = unsafe { *self.header };
        if hdr.caplen < hdr.len {
            println!("WARN: Capd only [{}] bytes of packet with length [{}]",
                     hdr.caplen, hdr.len);
        }
        if hdr.len > ETHERNET_HEADER_BYTES as u32 {
            unsafe {
                let ehp: *EthernetHeader = cast::transmute(self.packet);
                (*ehp).parse(ctx, hdr.len);
                (*ehp).dispatch(self, ctx);
            }
        }
    }
}

static ETHERNET_MAC_ADDR_BYTES: int = 6;
static ETHERNET_ETHERTYPE_BYTES: int = 2;
static ETHERNET_HEADER_BYTES: int =
    (ETHERNET_MAC_ADDR_BYTES * 2) + ETHERNET_ETHERTYPE_BYTES;

fixed_vec!(MacAddr, u8, ETHERNET_MAC_ADDR_BYTES)

impl ToStr for MacAddr {
    fn to_str(&self) -> ~str {
        let f = |x: u8,y| x.to_str_radix(y);
        return format!("{}:{}:{}:{}:{}:{}",
                       f(self[0], 16), f(self[1], 16), f(self[2], 16),
                       f(self[3], 16), f(self[4], 16), f(self[5], 16)
                      );
    }
}


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

fixed_vec!(IP4Addr, u8, 4)

impl ToStr for IP4Addr {
    fn to_str(&self) -> ~str {
        format!("{}.{}.{}.{}",
                self[0] as uint, self[1] as uint, self[2] as uint, self[3] as uint)
    }
}

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

fixed_vec!(IP6Addr, u16, 8)

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

extern fn handler(args: *u8, header: *pcap_pkthdr, packet: *u8) {
    unsafe {
        let ctx: *mut ProtocolHandlers = cast::transmute(args);
        let p = Packet { header: header, packet: packet };
        p.parse(&mut *ctx);
    }
}

fn main() {
    use extra::getopts::*;

    let PORT_OPT = "p";
    let INTERFACE_OPT = "i";
    let PROMISC_FLAG = "P";
    let MONITOR_FLAG = "M";

    let args = os::args();
    let opts = ~[
        optopt(PORT_OPT),
        optopt(INTERFACE_OPT),
        optflag(PROMISC_FLAG),
        optflag(MONITOR_FLAG)
    ];

    let matches = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()) }
    };

    let port = matches.opt_str(PORT_OPT).unwrap_or(~"7432");
    let port = from_str::<u16>(port).unwrap();

    let mc = Multicast::new();
    let data_ch = mc.get_chan();

    do named_task(~"socket_listener").spawn {
        uiServer(mc, port);
    }

    do named_task(~"packet_capture").spawn {
        let ctx = ~ProtocolHandlers {
            mac: ProtocolHandler::spawn("mac", &data_ch),
            ip4: ProtocolHandler::spawn("ip4", &data_ch),
            ip6: ProtocolHandler::spawn("ip6", &data_ch)
        };

        //FIXME: lame workaround for https://github.com/mozilla/rust/issues/11102
        std::io::timer::sleep(1000);

        let promisc = matches.opt_present(PROMISC_FLAG);
        let monitor = matches.opt_present(MONITOR_FLAG);
        let dev = matches.opt_str(INTERFACE_OPT);
        match dev {
            Some(d) => capture_loop_dev(d, promisc, monitor, ctx, handler),
            None => capture_loop(ctx, promisc, monitor, handler)
        };
    }
}
