use std::thread;
use std::hash::{Hash};
use std::collections::hash_map::{HashMap, Hasher};
use std::io::File;
use std::sync::{Arc,RwLock};
use std::sync::mpsc::{channel, Sender};
use std::thread::JoinGuard;

use toml;

use multicast::Multicast;
use json_serve::uiserver::UIServer;
use readline::readline;
use util::{ntohs, skip_bytes_cast, skip_cast};
use ip::{IP4Addr, IP6Addr, IP4Header, IP6Header};
use ether::{EthernetHeader, MacAddr,
            ETHERTYPE_ARP, ETHERTYPE_IP4, ETHERTYPE_IP6, ETHERTYPE_802_1X};
use dot11::{self, FrameType};
use tap;
use pkt_graph::{PktMeta, ProtocolGraph, RouteStats};


#[derive(RustcEncodable, Clone)]
struct RouteStatsMsg<T> {
    typ: &'static str,
    route: RouteStats<T>,
}

#[derive(Show)]
enum Pkt {
    Mac(PktMeta<MacAddr>),
    IP4(PktMeta<IP4Addr>),
    IP6(PktMeta<IP6Addr>),
}

#[derive(Clone)]
struct ProtocolHandler<T:Send+Sync> {
    typ: &'static str,
    graph: Arc<RwLock<ProtocolGraph<T>>>,
    stats_mcast: Multicast<RouteStatsMsg<T>>,
}

impl <T:Send+Sync+Copy+Clone+Eq+Hash<Hasher>> ProtocolHandler<T> {
    fn new(typ: &'static str) -> ProtocolHandler<T> {
        ProtocolHandler {
            typ: typ,
            graph: Arc::new(RwLock::new(ProtocolGraph::new())),
            stats_mcast: Multicast::spawn()
        }
    }

    fn update(&mut self, pkt: &PktMeta<T>) {
        let route_stats = {
            self.graph.write().unwrap().update(pkt)
        };
        let route_stats_msg = Arc::new(RouteStatsMsg {
            typ: self.typ,
            route: route_stats
        });
        self.stats_mcast.send(route_stats_msg);
    }
}

#[derive(Clone)]
struct ProtoGraphController {
    cap_tx: Sender<Pkt>,
    mac: ProtocolHandler<MacAddr>,
    ip4: ProtocolHandler<IP4Addr>,
    ip6: ProtocolHandler<IP6Addr>,
}

impl ProtoGraphController {
    fn spawn() -> ProtoGraphController {
        let (cap_tx, cap_rx) = channel();
        let ctl = ProtoGraphController {
            cap_tx: cap_tx,
            mac: ProtocolHandler::new("mac"),
            ip4: ProtocolHandler::new("ip4"),
            ip6: ProtocolHandler::new("ip6"),
        };

        let mut phctl = ctl.clone();
        thread::Builder::new().name("protocol_handler".to_string()).spawn(move || -> () {
            loop {
                let pkt = cap_rx.recv();
                if pkt.is_err() {
                    break
                }
                match pkt.unwrap() {
                    Pkt::Mac(ref p) => phctl.mac.update(p),
                    Pkt::IP4(ref p) => phctl.ip4.update(p),
                    Pkt::IP6(ref p) => phctl.ip6.update(p),
                }
            }
        });

        ctl
    }

    fn pkt_sender(&self) -> Sender<Pkt> {
        self.cap_tx.clone()
    }

    fn register_mac_listener(&self, s: Sender<Arc<RouteStatsMsg<MacAddr>>>) {
        self.mac.stats_mcast.register(s);
    }

    fn register_ip4_listener(&self, s: Sender<Arc<RouteStatsMsg<IP4Addr>>>) {
        self.ip4.stats_mcast.register(s);
    }

    fn register_ip6_listener(&self, s: Sender<Arc<RouteStatsMsg<IP6Addr>>>) {
        self.ip6.stats_mcast.register(s);
    }
}

trait CaptureCtx {
    fn parse(&mut self, pkt: *const u8, len: u32);
}

struct EthernetCtx {
    pkts: Sender<Pkt>,
}

impl CaptureCtx for EthernetCtx {
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

struct RadiotapCtx {
    pkts: Sender<Pkt>,
}

impl CaptureCtx for RadiotapCtx {
    fn parse(&mut self, pkt_ptr: *const u8, size: u32) {

        let tap_hdr = unsafe { &*(pkt_ptr as *const tap::RadiotapHeader) };

        fn magic<U>(pkt: &tap::RadiotapHeader) -> &U {
            unsafe { skip_bytes_cast(pkt, pkt.it_len as isize) }
        }

        let base: &dot11::Dot11BaseHeader = magic(tap_hdr);

        let fc = &base.fr_ctrl;
        if fc.protocol_version() != 0 {
            // bogus packet, bail
            return;
        }

        println!("frame_type: {:?}", fc.frame_type());
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
            &tap::COMMON_A => {
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
            &tap::COMMON_B => {
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

pub fn start_capture<'a>(conf: D3capConf, pkt_sender: Sender<Pkt>) -> JoinGuard<'a, ()> {
    use pcap::rustpcap as cap;

    thread::Builder::new().name("packet_capture".to_string()).scoped(move || {
        let sess = match conf.file {
            Some(ref f) => cap::PcapSession::from_file(&f[]),
            None => {
                let sess_builder = match conf.interface {
                    Some(ref dev) => cap::PcapSessionBuilder::new_dev(&dev[]),
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

        match sess.datalink() {
            cap::DLT_ETHERNET => go(&sess, &mut EthernetCtx { pkts: pkt_sender }),
            cap::DLT_IEEE802_11_RADIO => go(&sess, &mut RadiotapCtx { pkts: pkt_sender }),
            x => panic!("unsupported datalink type: {}", x)
        };
    })
}

fn start_cli<'a>(ctrl: D3capController) -> JoinGuard<'a, ()> {
    thread::Builder::new().name("cli".to_string()).scoped(move || {
        let mut ctrl = ctrl;

        let mut cmds: HashMap<String, (&str, Box<FnMut(Vec<&str>, &mut D3capController)>)>
            = HashMap::new();

        cmds.insert("ping".to_string(),
                    ("ping", Box::new(|&mut: _: Vec<&str>, _: &mut D3capController| {
                        println!("pong");
                    })));

        cmds.insert("websocket".to_string(),
                    ("websocket", Box::new(|&mut: cmd: Vec<&str>, ctrl: &mut D3capController| {
                        match &cmd[] {
                            [_, ref port] => {
                                if let Some(p) = port.parse() {
                                    ctrl.start_websocket(p);
                                }
                            },
                            [_] => ctrl.start_websocket(7432u16),
                            _ => println!("Illegal argument")
                        }
                    })));

        cmds.insert("ls".to_string(),
                    ("ls", Box::new(|&mut: cmd: Vec<&str>, ctrl: &mut D3capController| {
                        match &cmd[] {
                            [_, "mac"] => {
                                println!("{:?}", *ctrl.pg_ctrl.mac.graph.read().unwrap());
                            }
                            [_, "ip4"] => {
                                println!("{:?}", *ctrl.pg_ctrl.ip4.graph.read().unwrap());
                            }
                            [_, "ip6"] => {
                                println!("{:?}", *ctrl.pg_ctrl.ip6.graph.read().unwrap());
                            }
                            _ => println!("Illegal argument")
                        }
                    })));

        let maxlen = cmds.keys().map(|x| x.len()).max().unwrap();

        while let Some(val) = readline("> ") {
             let full_cmd: Vec<&str> = val.split(' ').collect();
             match full_cmd[0] {
                 "h" | "help" => {
                     println!("\nAvailable commands are:");
                     for (cmd, &(desc, _)) in cmds.iter() {
                         println!("    {:2$}\t{}", cmd, desc, maxlen);
                     }
                     println!("");
                 },
                 "q" | "quit" | "exit" => break,
                 "" => {}
                 cmd => match cmds.get_mut(cmd) {
                     Some(&mut (_, ref mut f)) => f(full_cmd, &mut ctrl),
                     None => println!("unknown command")
                 }
             }
        }
    })
}

// unboxed closure question:  why does http://is.gd/mlI7FS work but http://is.gd/yUbkvT blow up?  diff is in former closure takes String arg, latter it takes &str.  how would i get a ref arg to work?

fn load_mac_addrs(file: String) -> HashMap<MacAddr, String> {
    let s = File::open(&Path::new(file)).read_to_string().unwrap();
    let t = toml::Parser::new(&s[]).parse().unwrap();
    let known_macs = t.get(&"known-macs".to_string()).unwrap().as_table().unwrap();

    known_macs.iter()
        .map(|(k,v)| {
            (MacAddr::from_string(&k[]), v.as_str())
        })
        .filter_map(|x| match x {
            (Some(addr), Some(alias)) => Some((addr, alias.to_string())),
            _ => None
        })
        .collect()
}

fn start_websocket(port: u16, mac_addr_map: &MacMap, pg_ctl: &ProtoGraphController) {
    let ui = UIServer::spawn(port, mac_addr_map);
    pg_ctl.register_mac_listener(ui.create_sender());
    pg_ctl.register_ip4_listener(ui.create_sender());
    pg_ctl.register_ip6_listener(ui.create_sender());
}

type MacMap = HashMap<MacAddr, String>;

#[derive(Clone)]
pub struct D3capController {
    pg_ctrl: ProtoGraphController,
    mac_map: MacMap,
    server_started: bool
}

impl D3capController {
    fn spawn(conf: D3capConf) -> D3capController {
        let mac_map = conf.conf.as_ref()
            .map(|x| load_mac_addrs(x.to_string()))
            .unwrap_or_else(HashMap::new);

        let pg_ctrl = ProtoGraphController::spawn();

        start_capture(conf, pg_ctrl.pkt_sender()).detach();

        D3capController { pg_ctrl: pg_ctrl, mac_map: mac_map, server_started: false }
    }

    fn mac_map(&self) -> &MacMap {
        &self.mac_map
    }

    fn start_websocket(&mut self, port: u16) {
        if self.server_started {
            println!("server already started");
        } else {
            start_websocket(port, &self.mac_map, &self.pg_ctrl);
            self.server_started = true;
        }
    }
}

#[derive(Clone)]
pub struct D3capConf {
    pub websocket: Option<u16>,
    pub interface: Option<String>,
    pub file: Option<String>,
    pub conf: Option<String>,
    pub promisc: bool,
    pub monitor: bool
}

pub fn run(conf: D3capConf) {

    let mut ctrl = D3capController::spawn(conf.clone());

    // Only start the websocket server if the option is explicitly provided.
    if let Some(port) = conf.websocket {
        ctrl.start_websocket(port);
    }

    start_cli(ctrl).join();
}
