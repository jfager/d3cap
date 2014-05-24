use std;
use std::task::{TaskBuilder};
use std::hash::Hash;

use serialize::{json};
use serialize::json::ToJson;

use collections::treemap::TreeMap;
use collections::hashmap::HashMap;

use time;

use ring::RingBuffer;
use multicast::{Multicast, MulticastSender};
use uiserver::uiServer;
use util::{ntohs, trans_off};
use ip::{IP4Addr, IP6Addr, IP4Header, IP6Header};
use ether::{EthernetHeader, MacAddr,
            ETHERTYPE_ARP, ETHERTYPE_IP4, ETHERTYPE_IP6, ETHERTYPE_802_1X};
use dot11;
use tap;

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
    routes: HashMap<OrdAddrs<T>, Box<RouteStats<T>>>
}

impl<T: Ord+Hash+TotalEq+Clone+Send+ToStr> ProtocolHandler<T,StrBuf> {
    fn new(typ: &'static str, tx: MulticastSender<StrBuf>) -> ProtocolHandler<T,StrBuf> {
        //FIXME:  this is the map that's hitting https://github.com/mozilla/rust/issues/11102
        ProtocolHandler { typ: typ, count: 0, size: 0, tx: tx, routes: HashMap::new() }
    }
    fn update(&mut self, pkt: &PktMeta<T>) {
        let key = OrdAddrs::from(pkt.src.clone(), pkt.dst.clone());
        let typ = self.typ;
        let stats = self.routes.find_or_insert_with(key, |k| {
            let &OrdAddrs((ref v0, ref v1)) = k;
            box RouteStats::new(typ, v0.clone(), v1.clone())
        });
        stats.update(pkt);
        self.tx.send(route_msg(self.typ, *stats));
    }
    fn spawn(typ: &'static str, mc_tx: &MulticastSender<StrBuf>) -> Sender<PktMeta<T>> {
        let (tx, rx) = channel();
        let mc_tx = mc_tx.clone();
        TaskBuilder::new().named(format!("{}_handler", typ)).spawn(proc() {
            let mut handler = ProtocolHandler::new(typ, mc_tx);
            loop {
                handler.update(&rx.recv());
            }
        });
        tx
    }
}

fn route_msg<T:ToStr>(typ: &str, rt: &RouteStats<T>) -> StrBuf {
    let mut m = box TreeMap::new();
    m.insert("type".to_strbuf(), typ.to_strbuf().to_json());
    m.insert("a".to_strbuf(), rt.a.addr.to_str().to_strbuf().to_json());
    m.insert("from_a_count".to_strbuf(), rt.a.sent_count.to_json());
    m.insert("from_a_size".to_strbuf(), rt.a.sent_size.to_json());
    m.insert("b".to_strbuf(), rt.b.addr.to_str().to_strbuf().to_json());
    m.insert("from_b_count".to_strbuf(), rt.b.sent_count.to_json());
    m.insert("from_b_size".to_strbuf(), rt.b.sent_size.to_json());
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
    last: RingBuffer<PktMeta<T>>
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
    pub src: T,
    pub dst: T,
    pub size: u32,
    pub tm: time::Timespec
}
impl<T> PktMeta<T> {
    fn new(src: T, dst: T, size: u32) -> PktMeta<T> {
        PktMeta { src: src, dst: dst, size: size, tm: time::get_time() }
    }
}

struct EthernetCtx {
    mac: Sender<PktMeta<MacAddr>>,
    ip4: Sender<PktMeta<IP4Addr>>,
    ip6: Sender<PktMeta<IP6Addr>>
}

impl EthernetCtx {
    fn parse(&mut self, pkt: &EthernetHeader, size: u32) {
        self.mac.send(PktMeta::new(pkt.src, pkt.dst, size));
        self.dispatch(pkt);
    }

    fn dispatch(&mut self, pkt: &EthernetHeader) {
        match pkt.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => {
                let ipp: &IP4Header = unsafe { trans_off(pkt, 1) };
                self.ip4.send(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_IP6 => {
                let ipp: &IP6Header = unsafe { trans_off(pkt, 1) };
                self.ip6.send(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
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
    fn parse(&mut self, pkt: &tap::RadiotapHeader) {
        let wifiHeader: &dot11::Dot11MacBaseHeader = unsafe { trans_off(pkt, pkt.it_len as int) };
        let fc = wifiHeader.fr_ctrl;
        let proto_version = fc.protocol_version();
        if proto_version != 0 {
            //println!("Bogus packet (proto_version: {})", proto_version);
            return;
        }

        println!("frame_type: {:x}", fc.frame_type());
        println!("frame_subtype: {:x}", fc.frame_subtype());

        println!("toDS: {}", fc.has_flag(dot11::ToDS));
        println!("fromDS: {}", fc.has_flag(dot11::FromDS));
        println!("protected: {}", fc.has_flag(dot11::ProtectedFrame));

        println!("Mac1: {}", wifiHeader.addr1.to_str());

        match pkt.it_present {
            a if a == tap::COMMON_A => {
                match tap::CommonA::parse(pkt) {
                    Some(vals) => {
                        println!("tsft: {}", vals.tsft.timer_micros);
                        println!("channel: {}", vals.channel.mhz);
                        println!("antenna_signal: {}", vals.antenna_signal.dBm);
                        println!("antenna_noise: {}", vals.antenna_noise.dBm);
                        println!("antenna: {}", vals.antenna.idx);
                    },
                    _ => {
                        println!("Couldn't parse as CommonA");
                    }
                }
            },
            b if b == tap::COMMON_B => {
                match tap::CommonB::parse(pkt) {
                    Some(vals) => {
                        println!("tsft: {}", vals.tsft.timer_micros);
                        println!("channel: {}", vals.channel.mhz);
                        println!("antenna_signal: {}", vals.antenna_signal.dBm);
                        println!("antenna_noise: {}", vals.antenna_noise.dBm);
                        println!("antenna: {}", vals.antenna.idx);
                    },
                    _ => {
                        println!("Couldn't parse as CommonB");
                    }
                }
            },
            _ => {
                // println!("Unknown header!");
                // println!("has tsft? {}", pkt.has_field(tap::TSFT));
                // println!("has flags? {}", pkt.has_field(tap::FLAGS));
                // println!("has rate? {}", pkt.has_field(tap::RATE));
                // println!("has channel? {}", pkt.has_field(tap::CHANNEL));
                // println!("has fhss? {}", pkt.has_field(tap::FHSS));
                // println!("has antenna_signal? {}", pkt.has_field(tap::ANTENNA_SIGNAL));
                // println!("has antenna_noise? {}", pkt.has_field(tap::ANTENNA_NOISE));
                // println!("has lock_quality? {}", pkt.has_field(tap::LOCK_QUALITY));
                // println!("has tx_attenuation? {}", pkt.has_field(tap::TX_ATTENUATION));
                // println!("has db_tx_attenuation? {}", pkt.has_field(tap::DB_TX_ATTENUATION));
                // println!("has dbm_tx_power? {}", pkt.has_field(tap::DBM_TX_POWER));
                // println!("has antenna? {}", pkt.has_field(tap::ANTENNA));
                // println!("has db_antenna_signal? {}", pkt.has_field(tap::DB_ANTENNA_SIGNAL));
                // println!("has db_antenna_noise? {}", pkt.has_field(tap::DB_ANTENNA_NOISE));
                // println!("has rx_flags? {}", pkt.has_field(tap::RX_FLAGS));
                // println!("has mcs? {}", pkt.has_field(tap::MCS));
                // println!("has a_mpdu_status? {}", pkt.has_field(tap::A_MPDU_STATUS));
                // println!("has vht? {}", pkt.has_field(tap::VHT));
                // println!("has more_it_present? {}", pkt.has_field(tap::MORE_IT_PRESENT));
            }
        }
        println!("");
    }
}

pub fn run(conf: D3capConf) {
    use cap = pcap::rustpcap;

    let mc = Multicast::new();
    let data_tx = mc.get_sender();

    let port = conf.port;
    TaskBuilder::new().named("socket_listener").spawn(proc() {
        uiServer(mc, port);
    });

    TaskBuilder::new().named("packet_capture").spawn(proc() {

        let mut sessBuilder = match conf.interface {
            Some(ref dev) => cap::PcapSessionBuilder::new_dev(dev.as_slice()),
            None => cap::PcapSessionBuilder::new()
        };

        let sess = sessBuilder
            .buffer_size(65535)
            .timeout(1000)
            .promisc(conf.promisc)
            .rfmon(conf.monitor)
            .activate();

        println!("Starting capture loop");

        println!("Available datalink types: {:?}", sess.list_datalinks());

        match sess.datalink() {
            cap::DLT_ETHERNET => {
                let mut ctx = EthernetCtx {
                    mac: ProtocolHandler::spawn("mac", &data_tx),
                    ip4: ProtocolHandler::spawn("ip4", &data_tx),
                    ip6: ProtocolHandler::spawn("ip6", &data_tx)
                };

                //FIXME: lame workaround for https://github.com/mozilla/rust/issues/11102
                std::io::timer::sleep(1000);
                loop { sess.next(|t,sz| ctx.parse(t, sz)); }
            },
            cap::DLT_IEEE802_11_RADIO => {
                let mut ctx = RadiotapCtx;
                loop { sess.next(|t,_| ctx.parse(t)); }
            },
            x => fail!("unsupported datalink type: {}", x)
        }
    });
}

pub struct D3capConf {
    pub port: u16,
    pub interface: Option<StrBuf>,
    pub promisc: bool,
    pub monitor: bool
}
