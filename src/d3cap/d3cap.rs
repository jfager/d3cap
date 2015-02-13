use std::thread;
use std::hash::{Hash};
use std::iter;
use std::fmt::{Display};
use std::collections::hash_map::{Entry, HashMap, Hasher};
use std::old_io::{net, File};
use std::num::Float;
use std::sync::{Arc,RwLock};
use std::sync::mpsc::{channel, Sender};
use std::thread::JoinGuard;

use toml;

use multicast::Multicast;
use json_serve::uiserver::UIServer;
use readline::readline;
use util::{ntohs, skip_bytes_cast, skip_cast};
use ip::{AsStdIpAddr, IP4Addr, IP6Addr, IP4Header, IP6Header};
use ether::{EthernetHeader, MacAddr,
            ETHERTYPE_ARP, ETHERTYPE_IP4, ETHERTYPE_IP6, ETHERTYPE_802_1X};
use dot11::{self, FrameType};
use tap;
use pkt_graph::{PktMeta, ProtocolGraph, RouteStats};
use fixed_ring::FixedRingBuffer;
use pcap::rustpcap as cap;

#[derive(RustcEncodable, Clone)]
struct RouteStatsMsg<T> {
    typ: &'static str,
    route: RouteStats<T>,
}

#[derive(Debug)]
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
        thread::Builder::new().name("protocol_handler".to_string()).spawn(move || {
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

    fn sender(&self) -> Sender<Pkt> {
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
    fn parse(&mut self, pkt: &cap::PcapData);
}

struct EthernetCtx {
    pkts: Sender<Pkt>,
}

impl CaptureCtx for EthernetCtx {
    fn parse(&mut self, pkt: &cap::PcapData) {
        let ether_hdr = unsafe { &*(pkt.pkt_ptr() as *const EthernetHeader) };
        self.pkts.send(Pkt::Mac(PktMeta::new(ether_hdr.src, ether_hdr.dst, pkt.len())));
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
            _ => {
                //println!("Unknown type: {:x}", x);
            }
        }
    }
}

#[derive(Debug)]
struct PhysData { // TODO: this name sucks
    frame_ty: FrameType,
    addrs: [MacAddr; 3],
    rate: Option<tap::Rate>,
    channel: tap::Channel,
    antenna_signal: tap::AntennaSignal,
    antenna_noise: tap::AntennaNoise,
    antenna: tap::Antenna,
}

impl PhysData {
    fn new(frame_ty: FrameType,
           addrs: [MacAddr; 3],
           rate: Option<tap::Rate>,
           channel: tap::Channel,
           antenna_signal: tap::AntennaSignal,
           antenna_noise: tap::AntennaNoise,
           antenna: tap::Antenna,
           ) -> PhysData {
        PhysData {
            frame_ty: frame_ty,
            addrs: addrs,
            rate: rate,
            channel: channel,
            antenna_signal: antenna_signal,
            antenna_noise: antenna_noise,
            antenna: antenna
        }
    }

    fn dist(&self) -> f32 {
        let freq = self.channel.mhz as f32;
        let signal = self.antenna_signal.dbm as f32;

        let exp = (27.55 - (20.0 * freq.log10()) + signal.abs()) / 20.0;
        (10.0f32).powf(exp)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct PhysDataKey(FrameType, [MacAddr;3]);

struct PhysDataVal {
    dat: FixedRingBuffer<PhysData>,
    count: u32,
}

impl PhysDataVal {
    fn new() -> PhysDataVal {
        PhysDataVal {
            dat: FixedRingBuffer::new(10),
            count: 0
        }
    }

    fn avg_dist(&self) -> f32 {
        let mut s = 0.0;
        for pd in self.dat.iter() {
            s += pd.dist();
        }
        s / (self.dat.len() as f32)
    }

}

#[derive(Clone)]
struct PhysDataController {
    pd_tx: Sender<PhysData>,
    map:  Arc<RwLock<HashMap<PhysDataKey, PhysDataVal>>>
}

impl PhysDataController {
    fn spawn() -> PhysDataController {
        let (pd_tx, pd_rx) = channel();
        let out = PhysDataController {
            pd_tx: pd_tx,
            map: Arc::new(RwLock::new(HashMap::new()))
        };

        let ctl = out.clone();
        thread::Builder::new().name("physdata_handler".to_string()).spawn(move || {
            loop {
                let res = pd_rx.recv();
                if res.is_err() {
                    break
                }
                let pd = res.unwrap();

                match ctl.map.write().unwrap().entry(PhysDataKey(pd.frame_ty, pd.addrs)) {
                    Entry::Occupied(mut e) => {
                        let mut pdc = e.get_mut();
                        pdc.dat.push(pd);
                        pdc.count += 1;
                    }
                    Entry::Vacant(e) => {
                        let mut pdc = PhysDataVal::new();
                        pdc.dat.push(pd);
                        pdc.count += 1;
                        e.insert(pdc);
                    }
                };
            }
        });

        out
    }

    fn sender(&self) -> Sender<PhysData> {
        self.pd_tx.clone()
    }
}

trait TransAddr<T> {
    fn trans(&mut self, addr: &T) -> String;
}

impl TransAddr<MacAddr> for HashMap<MacAddr, String> {
    fn trans(&mut self, addr: &MacAddr) -> String {
        match self.get(addr) {
            Some(v) => v.clone(),
            None => addr.to_string()
        }
    }
}

impl<T:AsStdIpAddr+Eq+Hash<Hasher>+Display+Clone> TransAddr<T> for HashMap<T, String> {
    fn trans(&mut self, addr: &T) -> String {
        let k = addr.clone();
        match self.entry(k) {
            Entry::Occupied(e) => e.get().clone(),
            Entry::Vacant(e) => {
                let a = addr.as_std_ip();
                let n = match net::addrinfo::get_address_name(a) {
                    Ok(name) => name,
                    _ => addr.to_string()
                };
                let out = n.clone();
                e.insert(n);
                out
            }
        }
    }
}




struct RadiotapCtx {
    pkts: Sender<Pkt>,
    phys: Sender<PhysData>
}

impl RadiotapCtx {
    fn blah(&self, frame_ty: FrameType, addrs: [MacAddr; 3], tap_hdr: &tap::RadiotapHeader) {
        match &tap_hdr.it_present {
            &tap::COMMON_A => {
                if let Some(vals) = tap::CommonA::parse(tap_hdr) {
                    self.phys.send(PhysData::new(
                        frame_ty,
                        addrs,
                        Some(vals.rate),
                        vals.channel,
                        vals.antenna_signal,
                        vals.antenna_noise,
                        vals.antenna
                    ));
                }
            },
            &tap::COMMON_B => {
                if let Some(vals) = tap::CommonB::parse(tap_hdr) {
                    self.phys.send(PhysData::new(
                        frame_ty,
                        addrs,
                        None,
                        vals.channel,
                        vals.antenna_signal,
                        vals.antenna_noise,
                        vals.antenna
                    ));
                }
            },
            _ => {} //Unknown header
        }
    }
}


impl CaptureCtx for RadiotapCtx {
    fn parse(&mut self, pkt: &cap::PcapData) {

        let tap_hdr = unsafe { &*(pkt.pkt_ptr() as *const tap::RadiotapHeader) };

        fn magic<U>(pkt: &tap::RadiotapHeader) -> &U {
            unsafe { skip_bytes_cast(pkt, pkt.it_len as isize) }
        }

        let base: &dot11::Dot11BaseHeader = magic(tap_hdr);

        let fc = &base.fr_ctrl;
        if fc.protocol_version() != 0 {
            // bogus packet, bail
            return;
        }

        match fc.frame_type() {
            ft @ FrameType::Management => {
                let mgt: &dot11::ManagementFrameHeader = magic(tap_hdr);
                self.blah(ft, [mgt.addr1, mgt.addr2, mgt.addr3], tap_hdr);
            }
            FrameType::Control => {
                //println!("Control frame");
            }
            ft @ FrameType::Data => {
                let data: &dot11::DataFrameHeader = magic(tap_hdr);
                //TODO: get length
                self.pkts.send(Pkt::Mac(PktMeta::new(data.addr1, data.addr2, 1)));
                self.blah(ft, [data.addr1, data.addr2, data.addr3], tap_hdr);
            }
            FrameType::Unknown => {
                //println!("Unknown frame type");
            }
        }
    }

}

pub fn start_capture<'a>(conf: D3capConf,
                         pkt_sender: Sender<Pkt>,
                         pd_sender: Sender<PhysData>)
                         -> JoinGuard<'a, ()> {
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
            loop { sess.next(|cap| ctx.parse(cap)); }
        }

        match sess.datalink() {
            cap::DLT_ETHERNET => {
                go(&sess, &mut EthernetCtx { pkts: pkt_sender })
            }
            cap::DLT_IEEE802_11_RADIO => {
                go(&sess, &mut RadiotapCtx { pkts: pkt_sender, phys: pd_sender })
            }
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
                    ("ping", Box::new(|_, _| println!("pong"))));

        cmds.insert("websocket".to_string(),
                    ("websocket", Box::new(|cmd, ctrl| {
                        match &cmd[] {
                            [_, ref port] => {
                                if let Ok(p) = port.parse() {
                                    ctrl.start_websocket(p);
                                }
                            },
                            [_] => ctrl.start_websocket(7432u16),
                            _ => println!("Illegal argument")
                        }
                    })));

        fn print_ls_addr<A, T>(ph: &ProtocolHandler<A>, t: &mut T)
            where A: Eq+Hash<Hasher>+Copy+Clone+Display+Send+Sync,
                  T: TransAddr<A>
        {
            let graph = ph.graph.read().unwrap();
            let mut list: Vec<_> = graph.iter()
                .flat_map(|(src_addr, astats)| {
                    iter::repeat(src_addr).zip(astats.sent_iter())
                }).collect();

            list.sort_by(|a,b| (a.1).1.count.cmp(&(b.1).1.count).reverse());

            for &(src_addr, (dst_addr, pstats)) in list.iter() {
                println!("{} -> {}: count: {}, size: {}",
                         t.trans(&src_addr), t.trans(&dst_addr), pstats.count, pstats.size);
            }
        }

        fn print_ls_tap<T:TransAddr<MacAddr>>(pd_ctrl: &PhysDataController, macs: &mut T) {
            let m = pd_ctrl.map.read().unwrap();
            let mut list: Vec<_> = m.iter()
                .filter(|&(_, ref v)| v.dat.len() > 1).collect();

            list.sort_by(|a, b| a.1.avg_dist().partial_cmp(&b.1.avg_dist()).unwrap());

            for i in list.iter() {
                let (ref k, ref v) = *i;
                println!("{:?} [{}, {}, {}]: total: {}, curr_len: {}, dist: {}",
                         k.0,
                         macs.trans(&k.1[0]), macs.trans(&k.1[1]), macs.trans(&k.1[2]),
                         v.count, v.dat.len(), v.avg_dist());
            }
            println!("");
        }


        cmds.insert("ls".to_string(),
                    ("ls", Box::new(|cmd, ctrl| {
                        match &cmd[1..] {
                            ["mac"] => print_ls_addr(&ctrl.pg_ctrl.mac, &mut ctrl.mac_names),
                            ["ip4"] => print_ls_addr(&ctrl.pg_ctrl.ip4, &mut ctrl.ip4_names),
                            ["ip6"] => print_ls_addr(&ctrl.pg_ctrl.ip6, &mut ctrl.ip6_names),
                            ["tap"] => print_ls_tap(&ctrl.pd_ctrl, &mut ctrl.mac_names),
                            _ => println!("Illegal argument")
                        }
                    })));

        let maxlen = cmds.keys().map(|x| x.len()).max().unwrap();

        while let Some(val) = readline("> ") {
             let full_cmd: Vec<_> = val.split(' ').collect();
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

fn load_mac_addrs(file: String) -> HashMap<MacAddr, String> {
    let s = File::open(&Path::new(file)).read_to_string().unwrap();
    let mut parser = toml::Parser::new(&s[]);
    let t = parser.parse().unwrap();
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
type IP4Map = HashMap<IP4Addr, String>;
type IP6Map = HashMap<IP6Addr, String>;

#[derive(Clone)]
pub struct D3capController {
    pg_ctrl: ProtoGraphController,
    pd_ctrl: PhysDataController,
    mac_names: MacMap,
    ip4_names: IP4Map,
    ip6_names: IP6Map,
    server_started: bool
}

impl D3capController {
    fn spawn(conf: D3capConf) -> D3capController {
        let mac_names = conf.conf.as_ref()
            .map(|x| load_mac_addrs(x.to_string()))
            .unwrap_or_else(HashMap::new);
        let ip4_names = HashMap::new();
        let ip6_names = HashMap::new();

        let pg_ctrl = ProtoGraphController::spawn();
        let pd_ctrl = PhysDataController::spawn();

        start_capture(conf, pg_ctrl.sender(), pd_ctrl.sender()).detach();

        D3capController {
            pg_ctrl: pg_ctrl,
            pd_ctrl: pd_ctrl,
            mac_names: mac_names,
            ip4_names: ip4_names,
            ip6_names: ip6_names,
            server_started: false
        }
    }

    fn start_websocket(&mut self, port: u16) {
        if self.server_started {
            println!("server already started");
        } else {
            start_websocket(port, &self.mac_names, &self.pg_ctrl);
            self.server_started = true;
        }
    }
}

#[derive(Clone, Debug)]
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
