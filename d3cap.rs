#![feature(globs, macro_rules, default_type_params)]

extern crate std;
extern crate openssl;
extern crate getopts;
extern crate serialize;
extern crate collections;
extern crate time;

use std::{os};
use std::task::{task};
use std::hash::Hash;

use serialize::{json};
use serialize::json::ToJson;

use collections::treemap::TreeMap;
use collections::hashmap::HashMap;

use rustpcap::*;
use ring::RingBuffer;
use multicast::{Multicast, MulticastSender};
use uiserver::uiServer;
use util::*;
use ip::*;
use ether::*;
use dot11::*;

mod pcap;
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

#[deriving(Eq,TotalEq, Hash)]
struct OrdAddrs<T>(Addrs<T>);
impl<T: Ord+Hash> OrdAddrs<T> {
    fn from(a: T, b: T) -> OrdAddrs<T> {
        if a <= b { OrdAddrs((a, b)) } else { OrdAddrs((b, a)) }
    }
}

struct ProtocolHandler<T, C> {
    typ: &'static str,
    count: u64,
    size: u64,
    tx: MulticastSender<C>,
    routes: HashMap<~OrdAddrs<T>, ~RouteStats<T>>
}

impl<T: Ord+Hash+TotalEq+Clone+Send+ToStr> ProtocolHandler<T,~str> {
    fn new(typ: &'static str, tx: MulticastSender<~str>) -> ProtocolHandler<T,~str> {
        //FIXME:  this is the map that's hitting https://github.com/mozilla/rust/issues/11102
        ProtocolHandler { typ: typ, count: 0, size: 0, tx: tx, routes: HashMap::new() }
    }
    fn update(&mut self, pkt: &PktMeta<T>) {
        let key = ~OrdAddrs::from(pkt.src.clone(), pkt.dst.clone());
        let typ = self.typ;
        let stats = self.routes.find_or_insert_with(key, |k| {
            let &~OrdAddrs((ref v0, ref v1)) = k;
            ~RouteStats::new(typ, v0.clone(), v1.clone())
        });
        stats.update(pkt);
        self.tx.send(route_msg(self.typ, *stats));
    }
    fn spawn(typ: &'static str, mc_tx: &MulticastSender<~str>) -> Sender<~PktMeta<T>> {
        let (tx, rx) = channel();
        let mc_tx = mc_tx.clone();
        task().named(format!("{}_handler", typ)).spawn(proc() {
            let mut handler = ProtocolHandler::new(typ, mc_tx);
            loop {
                let pkt: ~PktMeta<T> = rx.recv();
                handler.update(pkt);
            }
        });
        tx
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

impl<T: Hash+Eq+Clone+Send+ToStr> RouteStats<T> {
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

struct EthernetCtx {
    mac: Sender<~PktMeta<MacAddr>>,
    ip4: Sender<~PktMeta<IP4Addr>>,
    ip6: Sender<~PktMeta<IP6Addr>>
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
                let ipp: &IP4Header = unsafe { trans_off(pkt, 1) };
                self.ip4.send(~PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_IP6 => {
                let ipp: &IP6Header = unsafe { trans_off(pkt, 1) };
                self.ip6.send(~PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_802_1X => {
                //io::println("802.1X!");
            },
            x => {
                println!("Unknown type: {:x}", x);
            }
        }
    }
}

struct RadiotapCtx;
impl RadiotapCtx {
    fn parse(&mut self, pkt: &RadiotapHeader) {
        println!("RadiotapHeader: {:?}", pkt);
        let wifiHeader: &Dot11MacBaseHeader = unsafe { trans_off(pkt, pkt.it_len as int) };
        let frc = wifiHeader.fr_ctrl;
        println!("protocol_version: {:x}, frame_type: {:x}, frame_subtype: {:x}, Mac1: {}",
                 frc.protocol_version(), frc.frame_type(), frc.frame_subtype(), wifiHeader.addr1.to_str());
    }
}

fn main() {
    use getopts::*;

    let port_opt = "p";
    let interface_opt = "i";
    let promisc_flag = "P";
    let monitor_flag = "M";

    let args = os::args();
    let opts = ~[
        optopt(port_opt, "port", "Websocket port", ""),
        optopt(interface_opt, "interface", "Network interface to listen on", ""),
        optflag(promisc_flag, "promisc", "Turn on promiscuous mode"),
        optflag(monitor_flag, "monitor", "Turn on monitor mode")
    ];

    let matches = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()) }
    };

    let port = matches.opt_str(port_opt).unwrap_or(~"7432");
    let port = from_str::<u16>(port).unwrap();

    let mc = Multicast::new();
    let data_tx = mc.get_sender();

    task().named(~"socket_listener").spawn(proc() {
        uiServer(mc, port);
    });

    task().named(~"packet_capture").spawn(proc() {

        let mut sessBuilder = match matches.opt_str(interface_opt) {
            Some(dev) => PcapSessionBuilder::new_dev(dev),
            None => PcapSessionBuilder::new()
        };

        let sess = sessBuilder
            .buffer_size(65535)
            .timeout(1000)
            .promisc(matches.opt_present(promisc_flag))
            .rfmon(matches.opt_present(monitor_flag))
            .activate();

        println!("Starting capture loop");

        println!("Available datalink types: {:?}", sess.list_datalinks());

        match sess.datalink() {
            DLT_ETHERNET => {
                let mut ctx = ~EthernetCtx {
                    mac: ProtocolHandler::spawn("mac", &data_tx),
                    ip4: ProtocolHandler::spawn("ip4", &data_tx),
                    ip6: ProtocolHandler::spawn("ip6", &data_tx)
                };

                //FIXME: lame workaround for https://github.com/mozilla/rust/issues/11102
                std::io::timer::sleep(1000);
                loop { sess.next(|t,sz| ctx.parse(t, sz)); }
            },
            DLT_IEEE802_11_RADIO => {
                let mut ctx = ~RadiotapCtx;
                loop { sess.next(|t,_| ctx.parse(t)); }
            },
            x => fail!("unsupported datalink type: {}", x)
        }
    });
}
