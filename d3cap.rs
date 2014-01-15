#[feature(globs, macro_rules)];

extern mod std;
extern mod extra;
extern mod crypto;

use std::{mem,os,ptr};
use std::hashmap::HashMap;

use extra::{json,time};
use extra::json::ToJson;
use extra::treemap::TreeMap;

use rustpcap::*;
use ring::RingBuffer;
use multicast::{Multicast, MulticastChan};
use uiserver::uiServer;
use util::*;
use ip::*;
use ether::*;
use dot11::*;

mod rustpcap;
mod ring;
mod rustwebsocket;
mod multicast;
mod fixed_vec_macros;
mod uiserver;
mod util;
mod ip;
mod ether;
mod dot11;

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
        let stats = self.routes.find_or_insert_with(key, |k_| {
            let &~OrdAddrs(ref k) = k_;
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
        PktMeta { src: src, dst: dst, size: size, time: time::get_time() }
    }
}
impl<T:Clone> PktMeta<T> {
    fn addrs(&self) -> Addrs<T> {
        (self.src.clone(), self.dst.clone())
    }
}

struct EthernetCtx {
    mac: Chan<~PktMeta<MacAddr>>,
    ip4: Chan<~PktMeta<IP4Addr>>,
    ip6: Chan<~PktMeta<IP6Addr>>
}

impl EthernetCtx {
    fn parse(&mut self, pkt: &EthernetHeader, size: u32) {
        self.mac.send(~PktMeta::new(pkt.src, pkt.dst, size));
        self.dispatch(pkt);
    }

    fn dispatch(&mut self, pkt: &EthernetHeader) {
        match pkt.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => {
                let ipp = unsafe { &*(ptr::offset(pkt, 1) as *IP4Header) };
                self.ip4.send(~PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_IP6 => {
                let ipp = unsafe { &*(ptr::offset(pkt, 1) as *IP6Header) };
                self.ip6.send(~PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
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

struct RadiotapCtx;
impl RadiotapCtx {
    fn parse(&mut self, pkt: &RadiotapHeader) {
        println!("RadiotapHeader: {:?}", pkt);
        let wifiHeader = unsafe {
            let us_pkt = ptr::to_unsafe_ptr(pkt);
            &*(ptr::offset(us_pkt as *u8, pkt.it_len as int) as *Dot11MacBaseHeader)
        };
        let frc = wifiHeader.fr_ctrl;
        println!("protocol_version: {:x}, frame_type: {:x}, frame_subtype: {:x}",
                 frc.protocol_version(), frc.frame_type(), frc.frame_subtype());
    }
}

extern fn ethernet_handler(args: *u8, header: *pcap_pkthdr, packet: *u8) {
    unsafe {
        let ctx = args as *mut EthernetCtx;
        (*ctx).parse(&*(packet as *EthernetHeader), (*header).len);
    }
}

extern fn radiotap_handler(args: *u8, header: *pcap_pkthdr, packet: *u8) {
    unsafe {
        let ctx = args as *mut RadiotapCtx;
        (*ctx).parse(&*(packet as *RadiotapHeader));
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

        let dev = matches.opt_str(INTERFACE_OPT);
        let mut sessBuilder = match dev {
            Some(d) => PcapSessionBuilder::new_dev(d),
            None => PcapSessionBuilder::new()
        };

        let mut sess = sessBuilder
            .buffer_size(65535)
            .timeout(1000)
            .promisc(matches.opt_present(PROMISC_FLAG))
            .rfmon(matches.opt_present(MONITOR_FLAG))
            .activate();

        println!("Starting capture loop");

        println!("Available datalink types: {:?}", sess.list_datalinks());

        match sess.datalink() {
            DLT_ETHERNET => {
                let ctx = ~EthernetCtx {
                    mac: ProtocolHandler::spawn("mac", &data_ch),
                    ip4: ProtocolHandler::spawn("ip4", &data_ch),
                    ip6: ProtocolHandler::spawn("ip6", &data_ch)
                };

                //FIXME: lame workaround for https://github.com/mozilla/rust/issues/11102
                std::io::timer::sleep(1000);
                sess.start_loop(ctx, ethernet_handler);
            },
            DLT_IEEE802_11_RADIO => {
                let ctx = ~RadiotapCtx;
                sess.start_loop(ctx, radiotap_handler);
            },
            x => fail!("unsupported datalink type: {}", x)
        }
    }
}
