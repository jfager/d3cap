use std::thread;
use std::hash::Hash;
use std::collections::HashMap;
use std::io::File;
use std::sync::Arc;
use std::thread::JoinGuard;
use std::time::duration::Duration;

use toml;

use multicast::Multicast;
use json_serve::uiserver::UIServer;
use readline::readline;
use ring::RingBuffer;
use util::{ntohs, skip_bytes_cast, skip_cast};
use ip::{IP4Addr, IP6Addr, IP4Header, IP6Header};
use ether::{EthernetHeader, MacAddr,
            ETHERTYPE_ARP, ETHERTYPE_IP4, ETHERTYPE_IP6, ETHERTYPE_802_1X};
use dot11::{mod, FrameType};
use tap;
use pkt_graph::{PktMeta, ProtocolGraph, RouteStats};


#[deriving(RustcEncodable, Clone)]
struct RouteStatsMsg<T> {
    typ: &'static str,
    route: RouteStats<T>,
}

#[deriving(Show)]
enum Pkt {
    Mac(PktMeta<MacAddr>),
    IP4(PktMeta<IP4Addr>),
    IP6(PktMeta<IP6Addr>),
}

struct ProtocolHandler<T:Send+Sync> {
    typ: &'static str,
    graph: ProtocolGraph<T>,
    stats_mcast: Multicast<RouteStatsMsg<T>>,
}

impl <T:Send+Sync+Copy+Eq+Hash> ProtocolHandler<T> {
    fn new(typ: &'static str) -> ProtocolHandler<T> {
        ProtocolHandler {
            typ: typ,
            graph: ProtocolGraph::new(),
            stats_mcast: Multicast::spawn()
        }
    }

    fn update(&mut self, pkt: &PktMeta<T>) {
        let route_stats = self.graph.update(pkt);
        let route_stats_msg = Arc::new(RouteStatsMsg {
            typ: self.typ,
            route: route_stats
        });
        self.stats_mcast.send(route_stats_msg);
    }
}

struct ProtoGraphController {
    cap_tx: Sender<Pkt>,
    req_tx: Sender<ProtoGraphReq>,
}

impl ProtoGraphController {
    fn spawn() -> ProtoGraphController {
        let (cap_tx, cap_rx) = channel();
        let (req_tx, req_rx) = channel();
        let foo = ProtoGraphController {
            cap_tx: cap_tx,
            req_tx: req_tx,
        };

        thread::Builder::new().name("protocol_handler".to_string()).spawn(move || {
            let mut mac = ProtocolHandler::new("mac");
            let mut ip4 = ProtocolHandler::new("ip4");
            let mut ip6 = ProtocolHandler::new("ip6");

            loop {
                select!(
                    pkt = cap_rx.recv() => {
                        match pkt {
                            Pkt::Mac(ref p) => mac.update(p),
                            Pkt::IP4(ref p) => ip4.update(p),
                            Pkt::IP6(ref p) => ip6.update(p),
                        }
                    },
                    request = req_rx.recv() => {
                        match request {
                            ProtoGraphReq::Ping(x) => x.send(ProtoGraphRsp::Pong),
                            ProtoGraphReq::MacStatListener(s) => mac.stats_mcast.register(s),
                            ProtoGraphReq::IP4StatListener(s) => ip4.stats_mcast.register(s),
                            ProtoGraphReq::IP6StatListener(s) => ip6.stats_mcast.register(s),
                        }
                    }
                )
            }
            ()
        }).detach();

        foo
    }

    fn pkt_sender(&self) -> &Sender<Pkt> {
        &self.cap_tx
    }

    fn req_sender(&self) -> &Sender<ProtoGraphReq> {
        &self.req_tx
    }
}

trait CaptureCtx {
    fn parse(&mut self, pkt: *const u8, len: u32);
}

struct EthernetCtx<'a> {
    pkts: &'a Sender<Pkt>,
}

impl <'a> CaptureCtx for EthernetCtx<'a> {
    fn parse(&mut self, pkt_ptr: *const u8, size: u32) {
        let ether_hdr = unsafe { &*(pkt_ptr as *const EthernetHeader) };
        self.pkts.send(Pkt::Mac(PktMeta::new(ether_hdr.src, ether_hdr.dst, size)));
        match ether_hdr.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => {
                let ipp: &IP4Header = unsafe { skip_cast(ether_hdr) };
                self.pkts.send(Pkt::IP4(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32)));
            },
            ETHERTYPE_IP6 => {
                let ipp: &IP6Header = unsafe { skip_cast(ether_hdr) };
                self.pkts.send(Pkt::IP6(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32)));
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

struct RadiotapCtx<'a> {
    pkts: &'a Sender<Pkt>,
}

impl <'a> CaptureCtx for RadiotapCtx<'a> {
    fn parse(&mut self, pkt_ptr: *const u8, size: u32) {

        let tap_hdr = unsafe { &*(pkt_ptr as *const tap::RadiotapHeader) };

        fn magic<U>(pkt: &tap::RadiotapHeader) -> &U {
            unsafe { skip_bytes_cast(pkt, pkt.it_len as int) }
        }

        let base: &dot11::Dot11BaseHeader = magic(tap_hdr);
        let fc = &base.fr_ctrl;
        if fc.protocol_version() != 0 {
            // bogus packet, bail
            return;
        }

        println!("frame_type: {}", fc.frame_type());
        println!("frame_subtype: {:x}", fc.frame_subtype());

        println!("toDS: {}", fc.has_flag(dot11::TO_DS));
        println!("fromDS: {}", fc.has_flag(dot11::FROM_DS));
        println!("protected: {}", fc.has_flag(dot11::PROTECTED_FRAME));

        match fc.frame_type() {
            FrameType::Management => {
                println!("Management frame");
                let mgt: &dot11::ManagementFrameHeader = magic(tap_hdr);
            }
            FrameType::Control => {
                println!("Control frame");
            }
            FrameType::Data => {
                println!("Data frame");
                let data: &dot11::DataFrameHeader = magic(tap_hdr);
                //TODO: get length
                self.pkts.send(Pkt::Mac(PktMeta::new(data.addr1, data.addr2, 1)));
            }
            FrameType::Unknown => {
                println!("Unknown frame type");
            }
        }

        match &tap_hdr.it_present {
            a @ &tap::COMMON_A => {
                match tap::CommonA::parse(tap_hdr) {
                    Some(vals) => {
                        println!("tsft: {}", vals.tsft.timer_micros);
                        println!("channel: {}", vals.channel.mhz);
                        println!("antenna_signal: {}", vals.antenna_signal.dbm);
                        println!("antenna_noise: {}", vals.antenna_noise.dbm);
                        println!("antenna: {}", vals.antenna.idx);
                    },
                    _ => {
                        println!("Couldn't parse as CommonA");
                    }
                }
            },
            b @ &tap::COMMON_B => {
                match tap::CommonB::parse(tap_hdr) {
                    Some(vals) => {
                        println!("tsft: {}", vals.tsft.timer_micros);
                        println!("channel: {}", vals.channel.mhz);
                        println!("antenna_signal: {}", vals.antenna_signal.dbm);
                        println!("antenna_noise: {}", vals.antenna_noise.dbm);
                        println!("antenna: {}", vals.antenna.idx);
                    },
                    _ => {
                        println!("Couldn't parse as CommonB");
                    }
                }
            },
            _ => {
                println!("Unknown header!");
                println!("has tsft? {}", tap_hdr.has_field(tap::TSFT));
                println!("has flags? {}", tap_hdr.has_field(tap::FLAGS));
                println!("has rate? {}", tap_hdr.has_field(tap::RATE));
                println!("has channel? {}", tap_hdr.has_field(tap::CHANNEL));
                println!("has fhss? {}", tap_hdr.has_field(tap::FHSS));
                println!("has antenna_signal? {}", tap_hdr.has_field(tap::ANTENNA_SIGNAL));
                println!("has antenna_noise? {}", tap_hdr.has_field(tap::ANTENNA_NOISE));
                println!("has lock_quality? {}", tap_hdr.has_field(tap::LOCK_QUALITY));
                println!("has tx_attenuation? {}", tap_hdr.has_field(tap::TX_ATTENUATION));
                println!("has db_tx_attenuation? {}", tap_hdr.has_field(tap::DB_TX_ATTENUATION));
                println!("has dbm_tx_power? {}", tap_hdr.has_field(tap::DBM_TX_POWER));
                println!("has antenna? {}", tap_hdr.has_field(tap::ANTENNA));
                println!("has db_antenna_signal? {}", tap_hdr.has_field(tap::DB_ANTENNA_SIGNAL));
                println!("has db_antenna_noise? {}", tap_hdr.has_field(tap::DB_ANTENNA_NOISE));
                println!("has rx_flags? {}", tap_hdr.has_field(tap::RX_FLAGS));
                println!("has mcs? {}", tap_hdr.has_field(tap::MCS));
                println!("has a_mpdu_status? {}", tap_hdr.has_field(tap::A_MPDU_STATUS));
                println!("has vht? {}", tap_hdr.has_field(tap::VHT));
                println!("has more_it_present? {}", tap_hdr.has_field(tap::MORE_IT_PRESENT));
            }
        }
        println!("");
    }
}

pub fn start_capture(conf: D3capConf) -> Sender<ProtoGraphReq> {
    use pcap::rustpcap as cap;

    let (tx, rx) = channel();

    thread::Builder::new().name("packet_capture".to_string()).spawn(move || {
        let sess = match conf.file {
            Some(ref f) => cap::PcapSession::from_file(f.as_slice()),
            None => {
                let mut sess_builder = match conf.interface {
                    Some(ref dev) => cap::PcapSessionBuilder::new_dev(dev.as_slice()),
                    None => cap::PcapSessionBuilder::new()
                };

                sess_builder.unwrap()
                    .buffer_size(65535)
                    .timeout(1000)
                    .promisc(conf.promisc)
                    .rfmon(conf.monitor)
                    .activate()
            }
        };

        fn go<T:CaptureCtx>(sess: &cap::PcapSession, ctx: &mut T) {
            loop { sess.next(|t,sz| ctx.parse(t, sz)); }
        }

        let foo = ProtoGraphController::spawn();
        tx.send(foo.req_sender().clone());

        match sess.datalink() {
            cap::DLT_ETHERNET => go(&sess, &mut EthernetCtx {
                pkts: foo.pkt_sender()
            }),
            cap::DLT_IEEE802_11_RADIO => go(&sess, &mut RadiotapCtx {
                pkts: foo.pkt_sender()
            }),
            x => panic!("unsupported datalink type: {}", x)
        };
        ()
    }).detach();

    rx.recv()
}

enum ProtoGraphReq {
    Ping(Sender<ProtoGraphRsp>),
    MacStatListener(Sender<Arc<RouteStatsMsg<MacAddr>>>),
    IP4StatListener(Sender<Arc<RouteStatsMsg<IP4Addr>>>),
    IP6StatListener(Sender<Arc<RouteStatsMsg<IP6Addr>>>),
}

#[deriving(Show)]
enum ProtoGraphRsp {
    Pong
}

fn start_cli(tx: Sender<CtrlReq>) -> JoinGuard<()> {
    let (my_tx, my_rx) = channel();

    thread::Builder::new().name("cli".to_string()).spawn(move || {
        let mut cmds: HashMap<String, (&str, ||->())> = HashMap::new();
        cmds.insert("ping".to_string(), ("ping", || {
            tx.send(CtrlReq::Ping(my_tx.clone()));
            match my_rx.recv() {
                CtrlRsp::Pong => println!("pong"),
            }
        }));

        let maxlen = cmds.keys().map(|x| x.len()).max().unwrap();

        while let Some(val) = readline("> ") {
            match val.as_slice() {
                "help" => {
                    println!("\nAvailable commands are:");
                    for (cmd, &(desc, _)) in cmds.iter() {
                        println!("    {:2$}\t{}", cmd, desc, maxlen);
                    }
                    println!("");
                },
                "" => {}
                _ => match cmds.get_mut(&val) {
                    Some(&(_, ref mut f)) => (*f)(),
                    None => println!("unknown command")
                }
            }
        }
        ()
    })
}

enum CtrlReq {
    Ping(Sender<CtrlRsp>),
    StartWebSocket(u16)
}

enum CtrlRsp {
    Pong
}

fn load_mac_addrs(file: String) -> HashMap<MacAddr, String> {
    let s = File::open(&Path::new(file)).read_to_string().unwrap();
    let t = toml::Parser::new(s.as_slice()).parse().unwrap();
    let known_macs = t.get(&"known-macs".to_string()).unwrap().as_table().unwrap();

    known_macs.iter()
        .map(|(k,v)| {
            (MacAddr::from_string(k.as_slice()), v.as_str())
        })
        .filter_map(|x| match x {
            (Some(addr), Some(alias)) => Some((addr, alias.to_string())),
            _ => None
        })
        .collect()
}

fn start_web_socket(port: u16, mac_addr_map: &MacMap, caps: &Sender<ProtoGraphReq>) {
    let ui = UIServer::spawn(port, mac_addr_map);
    caps.send(ProtoGraphReq::MacStatListener(ui.create_sender()));
    caps.send(ProtoGraphReq::IP4StatListener(ui.create_sender()));
    caps.send(ProtoGraphReq::IP6StatListener(ui.create_sender()));
}

type MacMap = HashMap<MacAddr, String>;

pub struct D3capController {
    mac_addr_map: MacMap,
    tx: Sender<CtrlReq>
}

impl D3capController {
    fn spawn(conf: D3capConf) -> D3capController {
        let mac_map = conf.conf.as_ref()
            .map(|x| load_mac_addrs(x.to_string()))
            .unwrap_or_else(HashMap::new);

        let (tx, rx) = channel();
        let out = D3capController { mac_addr_map: mac_map.clone(), tx: tx };
        let cap_snd = start_capture(conf);

        thread::Builder::new().name("controller".to_string()).spawn(move || {
            let caps = cap_snd.clone();
            loop {
                match rx.recv() {
                    CtrlReq::Ping(s) => s.send(CtrlRsp::Pong),
                    CtrlReq::StartWebSocket(port) => start_web_socket(port, &mac_map, &caps)
                }
            }
            ()
        }).detach();

        out
    }

    fn mac_addr_map(&self) -> &HashMap<MacAddr, String> {
        &self.mac_addr_map
    }

    fn get_sender(&self) -> Sender<CtrlReq> {
        self.tx.clone()
    }
}


pub struct D3capConf {
    pub websocket: Option<u16>,
    pub interface: Option<String>,
    pub file: Option<String>,
    pub conf: Option<String>,
    pub promisc: bool,
    pub monitor: bool
}

pub fn run(conf: D3capConf) {

    let mut ctrl = D3capController::spawn(conf);

    let mut sndr = ctrl.get_sender();

    sndr.send(CtrlReq::StartWebSocket(7432u16));

    start_cli(sndr);
}
