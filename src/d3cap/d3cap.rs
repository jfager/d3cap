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
    route: RouteStats<T>
}

struct ProtocolHandler<T:Send+Sync> {
    cap_tx: Sender<PktMeta<T>>,
    req_tx: Sender<ProtoGraphReq>,
    route_stats_mcast: Multicast<RouteStatsMsg<T>>
}

impl <T: Hash+Eq+Copy+Send+Sync> ProtocolHandler<T> {
    fn spawn(typ: &'static str) -> ProtocolHandler<T> {
        let (cap_tx, cap_rx) = channel();
        let (req_tx, req_rx) = channel();
        let handler = ProtocolHandler {
            cap_tx: cap_tx,
            req_tx: req_tx,
            route_stats_mcast: Multicast::spawn()
        };

        let mc_sender = handler.route_stats_mcast.clone();
        thread::Builder::new().name(format!("{}_handler", typ)).spawn(move || {
            let mut stats = ProtocolGraph::new();
            loop {
                select!(
                    update = cap_rx.recv() => {
                        let route_stats = stats.update(&update);
                        let route_stats_msg = Arc::new(RouteStatsMsg {
                            typ: typ,
                            route: route_stats
                        });
                        mc_sender.send(route_stats_msg);
                    },
                    request = req_rx.recv() => {
                        match request {
                            ProtoGraphReq::Ping(x) => x.send(ProtoGraphRsp::Pong),
                            //ProtoGraphReq::RegRouteStatsListenerMac(s) => {},
                            //ProtoGraphReq::RegRouteStatsListenerIP4(s) => {},
                            //ProtoGraphReq::RegRouteStatsListenerIP6(s) => {},
                        }
                    }
                )
            }
            ()
        }).detach();

        handler
    }

    fn pkt_sender(&self) -> &Sender<PktMeta<T>> {
        &self.cap_tx
    }

    fn req_sender(&self) -> &Sender<ProtoGraphReq> {
        &self.req_tx
    }

    fn register_route_stats_listener(&self, tx: Sender<Arc<RouteStatsMsg<T>>>) {
        self.route_stats_mcast.register(tx);
    }
}

impl <T:Send+Sync> Clone for ProtocolHandler<T> {
    fn clone(&self) -> ProtocolHandler<T> {
        ProtocolHandler {
            cap_tx: self.cap_tx.clone(),
            req_tx: self.req_tx.clone(),
            route_stats_mcast: self.route_stats_mcast.clone()
        }
    }
}

trait CaptureCtx {
    fn parse(&mut self, pkt: *const u8, len: u32);
    fn get_sender(&self) -> Sender<ProtoGraphReq>;
}

struct EthernetCtx {
    mac: ProtocolHandler<MacAddr>,
    ip4: ProtocolHandler<IP4Addr>,
    ip6: ProtocolHandler<IP6Addr>
}

impl CaptureCtx for EthernetCtx {
    fn parse(&mut self, pkt_ptr: *const u8, size: u32) {
        let ether_hdr = unsafe { &*(pkt_ptr as *const EthernetHeader) };
        self.mac.pkt_sender().send(PktMeta::new(ether_hdr.src, ether_hdr.dst, size));
        match ether_hdr.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => {
                let ipp: &IP4Header = unsafe { skip_cast(ether_hdr) };
                self.ip4.pkt_sender().send(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_IP6 => {
                let ipp: &IP6Header = unsafe { skip_cast(ether_hdr) };
                self.ip6.pkt_sender().send(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_802_1X => {
                //io::println("802.1X!");
            },
            x => {
                println!("Unknown type: {:x}", x);
            }
        }
    }

    fn get_sender(&self) -> Sender<ProtoGraphReq> {
        let (tx, rx): (Sender<ProtoGraphReq>, Receiver<ProtoGraphReq>) = channel();
        let mac_tx = self.mac.req_sender().clone();
        let ip4_tx = self.ip4.req_sender().clone();
        let ip6_tx = self.ip6.req_sender().clone();
        thread::Builder::new().name("EthernetCtx".to_string()).spawn(move || {
            loop {
                match rx.recv() {
                    //s @ ProtoGraphReq::RegRouteStatsListenerMac(_) => mac_tx.send(s),
                    //s @ ProtoGraphReq::RegRouteStatsListenerIP4(_) => ip4_tx.send(s),
                    //s @ ProtoGraphReq::RegRouteStatsListenerIP6(_) => ip6_tx.send(s),
                    _ => {}
                }
            }
            ()
        }).detach();
        tx
    }
}

struct RadiotapCtx {
    mac: ProtocolHandler<MacAddr>
}

impl CaptureCtx for RadiotapCtx {
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
                self.mac.pkt_sender().send(PktMeta::new(data.addr1, data.addr2, 1));
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

    fn get_sender(&self) -> Sender<ProtoGraphReq> {
        let (tx, rx): (Sender<ProtoGraphReq>, Receiver<ProtoGraphReq>) = channel();
        let mac_tx = self.mac.req_sender().clone();
        thread::Builder::new().name("RadiotapCtx".to_string()).spawn(move || {
            loop {
                match rx.recv() {
                    //s @ ProtoGraphReq::RegRouteStatsListenerMac(_) => mac_tx.send(s),
                    _ => {}// do nothing
                }
            }
            ()
        }).detach();
        tx
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

        fn go<T:CaptureCtx>(sess: &cap::PcapSession, tx: &Sender<Sender<ProtoGraphReq>>, ctx: &mut T) {
            tx.send(ctx.get_sender());
            loop { sess.next(|t,sz| ctx.parse(t, sz)); }
        }

        match sess.datalink() {
            cap::DLT_ETHERNET => go(&sess, &tx, &mut EthernetCtx {
                mac: ProtocolHandler::spawn("mac"),
                ip4: ProtocolHandler::spawn("ip4"),
                ip6: ProtocolHandler::spawn("ip6")
            }),
            cap::DLT_IEEE802_11_RADIO => go(&sess, &tx, &mut RadiotapCtx {
                mac: ProtocolHandler::spawn("mac"),
            }),
            x => panic!("unsupported datalink type: {}", x)
        };
        ()
    }).detach();

    rx.recv()
}

enum ProtoGraphReq {
    Ping(Sender<ProtoGraphRsp>),
    //RegRouteStatsListenerMac(|Arc<RouteStatsMsg<MacAddr>>|:'a, ()>),
    //RegRouteStatsListenerIP4(|Arc<RouteStatsMsg<IP4Addr>>|:'a, ()>),
    //RegRouteStatsListenerIP6(|Arc<RouteStatsMsg<IP6Addr>>|:'a, ()>),
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

        loop {
            readline("> ").map(|val| match val.as_slice() {
                "help" => {
                    println!("\nAvailable commands are:");
                    for (cmd, &(desc, _)) in cmds.iter() {
                        println!("    {:2$}\t{}", cmd, desc, maxlen);
                    }
                    println!("");
                },
                _ => match cmds.get_mut(&val) {
                    Some(&(_, ref mut f)) => (*f)(),
                    None => println!("unknown command")
                }
            });
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
    //caps.send(ProtoGraphReq::RegRouteStatsListenerMac(ui.create_sender()));
    //caps.send(ProtoGraphReq::RegRouteStatsListenerIP4(ui.create_sender()));
    //caps.send(ProtoGraphReq::RegRouteStatsListenerIP6(ui.create_sender()));
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
            let caps = cap_snd;
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

    start_cli(ctrl.get_sender());
}
