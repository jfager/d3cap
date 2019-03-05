use std::thread::{self, JoinHandle};
use std::hash::{Hash};
use std::collections::hash_map::{Entry, HashMap};
use std::fs::File;
use std::io::{self, Read};
use std::sync::{Arc,RwLock};
use crossbeam::channel::{unbounded, Sender, SendError};

use toml;

use multicast::Multicast;
use json_serve::uiserver::UIServer;

use crate::util::{ntohs, skip_bytes_cast, skip_cast};
use crate::ip::{IP4Addr, IP6Addr, IP4Header, IP6Header};
use crate::ether::{EthernetHeader, MacAddr,
            ETHERTYPE_ARP, ETHERTYPE_IP4, ETHERTYPE_IP6, ETHERTYPE_802_1X};
use crate::dot11::{self, FrameType};
use crate::tap;
use crate::pkt_graph::{PktMeta, ProtocolGraph, RouteStats};
use fixed_ring::FixedRingBuffer;
use pcap::pcap as cap;


#[derive(RustcEncodable, Clone)]
struct RouteStatsMsg<T> {
    typ: &'static str,
    route: RouteStats<T>,
}

#[derive(Debug)]
pub enum Pkt {
    Mac(PktMeta<MacAddr>),
    IP4(PktMeta<IP4Addr>),
    IP6(PktMeta<IP6Addr>),
}

#[derive(Clone)]
pub struct ProtocolHandler<T:Eq+Hash+Send+Sync+'static> {
    pub typ: &'static str,
    pub graph: Arc<RwLock<ProtocolGraph<T>>>,
    stats_mcast: Multicast<RouteStatsMsg<T>>,
}

impl <T:Send+Sync+Copy+Clone+Eq+Hash> ProtocolHandler<T> {
    fn new(typ: &'static str) -> io::Result<ProtocolHandler<T>> {
        Ok(ProtocolHandler {
            typ,
            graph: Arc::new(RwLock::new(ProtocolGraph::new())),
            stats_mcast: Multicast::spawn()?
        })
    }

    fn update(&mut self, pkt: &PktMeta<T>) {
        let route_stats = {
            self.graph.write().unwrap().update(pkt)
        };
        let route_stats_msg = Arc::new(RouteStatsMsg {
            typ: self.typ,
            route: route_stats
        });
        self.stats_mcast.send(route_stats_msg).unwrap();
    }
}

#[derive(Clone)]
pub struct ProtoGraphController {
    pub cap_tx: Sender<Pkt>,
    pub mac: ProtocolHandler<MacAddr>,
    pub ip4: ProtocolHandler<IP4Addr>,
    pub ip6: ProtocolHandler<IP6Addr>,
}

impl ProtoGraphController {
    fn spawn() -> io::Result<ProtoGraphController> {
        let (cap_tx, cap_rx) = unbounded();
        let ctl = ProtoGraphController {
            cap_tx,
            mac: ProtocolHandler::new("mac")?,
            ip4: ProtocolHandler::new("ip4")?,
            ip6: ProtocolHandler::new("ip6")?,
        };

        let mut phctl = ctl.clone();
        thread::Builder::new().name("protocol_handler".to_owned()).spawn(move || {
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
        })?;

        Ok(ctl)
    }

    fn sender(&self) -> Sender<Pkt> {
        self.cap_tx.clone()
    }

    fn register_mac_listener(&self, s: Sender<Arc<RouteStatsMsg<MacAddr>>>) {
        self.mac.stats_mcast.register(s).unwrap();
    }

    fn register_ip4_listener(&self, s: Sender<Arc<RouteStatsMsg<IP4Addr>>>) {
        self.ip4.stats_mcast.register(s).unwrap();
    }

    fn register_ip6_listener(&self, s: Sender<Arc<RouteStatsMsg<IP6Addr>>>) {
        self.ip6.stats_mcast.register(s).unwrap();
    }
}

enum ParseErr {
    Send,
    UnknownPacket
}

impl<T> From<SendError<T>> for ParseErr {
    fn from(_: SendError<T>) -> ParseErr {
        ParseErr::Send
    }
}

trait PktParser {
    fn parse(&mut self, pkt: &cap::PcapData) -> Result<(), ParseErr>;
}

pub struct CaptureCtx {
    sess: cap::PcapSession,
    parser: Box<PktParser+'static>
}

impl CaptureCtx {
    fn parse_next(&mut self) {
        let p = &mut self.parser;
        self.sess.next(|cap| {
            match p.parse(cap) {
                _ => () //just ignore
            }
        });
    }
}

struct EthernetParser {
    pkts: Sender<Pkt>,
}

impl PktParser for EthernetParser {

    fn parse(&mut self, pkt: &cap::PcapData) -> Result<(), ParseErr> {
        let ether_hdr = unsafe { &*(pkt.pkt_ptr() as *const EthernetHeader) };
        self.pkts.send(Pkt::Mac(PktMeta::new(ether_hdr.src, ether_hdr.dst, pkt.len())))?;
        match ether_hdr.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => {
                let ipp: &IP4Header = unsafe { skip_cast(ether_hdr) };
                self.pkts.send(Pkt::IP4(PktMeta::new(ipp.src, ipp.dst, u32::from(ntohs(ipp.len)))))?;
            },
            ETHERTYPE_IP6 => {
                let ipp: &IP6Header = unsafe { skip_cast(ether_hdr) };
                self.pkts.send(Pkt::IP6(PktMeta::new(ipp.src, ipp.dst, u32::from(ntohs(ipp.len)))))?;
            },
            ETHERTYPE_802_1X => {
                //io::println("802.1X!");
            },
            _ => {
                //println!("Unknown type: {:x}", x);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PhysData { // TODO: this name sucks
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
        PhysData { frame_ty, addrs, rate, channel, antenna_signal, antenna_noise, antenna }
    }

    fn dist(&self) -> f32 {
        let freq = f32::from(self.channel.mhz);
        let signal = f32::from(self.antenna_signal.dbm);

        let exp = (27.55 - (20.0 * freq.log10()) + signal.abs()) / 20.0;
        (10.0f32).powf(exp)
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct PhysDataKey(pub FrameType, pub [MacAddr;3]);

pub struct PhysDataVal {
    pub dat: FixedRingBuffer<PhysData>,
    pub count: u32,
}

impl PhysDataVal {
    pub fn new() -> PhysDataVal {
        PhysDataVal {
            dat: FixedRingBuffer::new(10),
            count: 0
        }
    }

    pub fn avg_dist(&self) -> f32 {
        let mut s = 0.0;
        for pd in self.dat.iter() {
            s += pd.dist();
        }
        s / (self.dat.len() as f32)
    }

}

#[derive(Clone)]
pub struct PhysDataController {
    pub map:  Arc<RwLock<HashMap<PhysDataKey, PhysDataVal>>>,
    pd_tx: Sender<PhysData>
}

impl PhysDataController {
    fn spawn() -> io::Result<PhysDataController> {
        let (pd_tx, pd_rx) = unbounded();
        let out = PhysDataController {
            pd_tx,
            map: Arc::new(RwLock::new(HashMap::new()))
        };

        let ctl = out.clone();
        thread::Builder::new().name("physdata_handler".to_owned()).spawn(move || {
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
        })?;

        Ok(out)
    }

    fn sender(&self) -> Sender<PhysData> {
        self.pd_tx.clone()
    }
}

struct RadiotapParser {
    pkts: Sender<Pkt>,
    phys: Sender<PhysData>
}

impl RadiotapParser {
    fn parse_known_headers(&self,
                           frame_ty: FrameType,
                           addrs: [MacAddr; 3],
                           tap_hdr: &tap::RadiotapHeader) {
        match tap_hdr.it_present {
            tap::ItPresent::COMMON_A => {
                if let Some(vals) = tap::CommonA::parse(tap_hdr) {
                    self.phys.send(PhysData::new(
                        frame_ty,
                        addrs,
                        Some(vals.rate),
                        vals.channel,
                        vals.antenna_signal,
                        vals.antenna_noise,
                        vals.antenna
                    )).unwrap();
                }
            },
            tap::ItPresent::COMMON_B => {
                if let Some(vals) = tap::CommonB::parse(tap_hdr) {
                    self.phys.send(PhysData::new(
                        frame_ty,
                        addrs,
                        None,
                        vals.channel,
                        vals.antenna_signal,
                        vals.antenna_noise,
                        vals.antenna
                    )).unwrap();
                }
            },
            _ => {} //Unknown header
        }
    }
}


impl PktParser for RadiotapParser {
    fn parse(&mut self, pkt: &cap::PcapData) ->  Result<(), ParseErr> {
        fn magic<U>(pkt: &tap::RadiotapHeader) -> &U {
            unsafe { skip_bytes_cast(pkt, pkt.it_len as isize) }
        }

        let tap_hdr = unsafe { &*(pkt.pkt_ptr() as *const tap::RadiotapHeader) };
        let base: &dot11::Dot11BaseHeader = magic(tap_hdr);

        let fc = &base.fr_ctrl;
        if fc.protocol_version() != 0 {
            // bogus packet, bail
            return Err(ParseErr::UnknownPacket);
        }

        match fc.frame_type() {
            ft @ FrameType::Management => {
                let mgt: &dot11::ManagementFrameHeader = magic(tap_hdr);
                self.parse_known_headers(ft, [mgt.addr1, mgt.addr2, mgt.addr3], tap_hdr);
            }
            ft @ FrameType::Data => {
                let data: &dot11::DataFrameHeader = magic(tap_hdr);
                //TODO: get length
                self.pkts.send(Pkt::Mac(PktMeta::new(data.addr1, data.addr2, 1)))?;
                self.parse_known_headers(ft, [data.addr1, data.addr2, data.addr3], tap_hdr);
            }
            FrameType::Control | FrameType::Unknown => {
                //println!("Unknown frame type");
            }
        }
        Ok(())
    }

}

pub fn init_capture(conf: &D3capConf,
                    pkt_sender: Sender<Pkt>,
                    pd_sender: Sender<PhysData>) -> CaptureCtx {
    let sess = match conf.file {
        Some(ref f) => cap::PcapSession::from_file(f),
        None => {
            println!("No session file");
            let sess_builder = match conf.interface {
                Some(ref dev) => cap::PcapSessionBuilder::new_dev(dev),
                None => cap::PcapSessionBuilder::new()
            };

            sess_builder.unwrap()
                .buffer_size(0xFFFF)
                .timeout(1000)
                .promisc(conf.promisc)
                .rfmon(conf.monitor)
                .activate()
        }
    };

    let parser = match sess.datalink() {
        cap::DLT_ETHERNET => {
            Box::new(EthernetParser { pkts: pkt_sender }) as Box<PktParser>
        }
        cap::DLT_IEEE802_11_RADIO => {
            Box::new(RadiotapParser { pkts: pkt_sender, phys: pd_sender }) as Box<PktParser>
        }
        x => panic!("unsupported datalink type: {}", x)
    };

    CaptureCtx { sess, parser }
}

pub fn start_capture(conf: D3capConf,
                     pkt_sender: Sender<Pkt>,
                     pd_sender: Sender<PhysData>) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name("packet_capture".to_owned()).spawn(move || {
        let mut cap = init_capture(&conf, pkt_sender, pd_sender);
        loop {
            cap.parse_next();
        }
    })
}

enum LoadMacError {
    IOError(io::Error),
    TomlError(Option<toml::de::Error>)
}
impl From<io::Error> for LoadMacError {
    fn from(err: io::Error) -> LoadMacError {
        LoadMacError::IOError(err)
    }
}
impl From<toml::de::Error> for LoadMacError {
    fn from(err: toml::de::Error) -> LoadMacError { LoadMacError::TomlError(Some(err)) }
}

fn load_mac_addrs(file: &str) -> Result<HashMap<MacAddr, String>, LoadMacError> {
    let mut s = String::new();

    let mut f = File::open(&file)?;
    f.read_to_string(&mut s)?;

    let t = s.parse::<toml::Value>()?;
    if let Some(k) = t.get(&"known-macs".to_owned()) {
        if let Some(tbl) = k.as_table() {
            return Ok(tbl.iter()
                .map(|(k, v)| (MacAddr::from_string(k), v.as_str()))
                .filter_map(|x| match x {
                    (Some(addr), Some(alias)) => Some((addr, alias.to_owned())),
                    _ => None
                })
                .collect())
        }
    }
    Err(LoadMacError::TomlError(None))
}

fn start_websocket(port: u16, mac_map: &MacMap, pg_ctl: &ProtoGraphController) -> io::Result<()> {
    let ui = UIServer::spawn(port, mac_map)?;
    pg_ctl.register_mac_listener(ui.create_sender()?);
    pg_ctl.register_ip4_listener(ui.create_sender()?);
    pg_ctl.register_ip6_listener(ui.create_sender()?);
    Ok(())
}

pub type MacMap = HashMap<MacAddr, String>;
pub type IP4Map = HashMap<IP4Addr, String>;
pub type IP6Map = HashMap<IP6Addr, String>;

#[derive(Clone)]
pub struct D3capController {
    pub pg_ctrl: ProtoGraphController,
    pub pd_ctrl: PhysDataController,
    pub mac_names: MacMap,
    pub ip4_names: IP4Map,
    pub ip6_names: IP6Map,
    pub server_started: bool
}

impl D3capController {
    pub fn spawn(conf: D3capConf) -> io::Result<D3capController> {
        let mac_names = conf.conf.as_ref()
            .map_or_else(HashMap::new, |x| {
                load_mac_addrs(x).unwrap_or_else(|_| HashMap::new())
            });
        let ip4_names = HashMap::new();
        let ip6_names = HashMap::new();

        let pg_ctrl = ProtoGraphController::spawn()?;
        let pd_ctrl = PhysDataController::spawn()?;

        start_capture(conf, pg_ctrl.sender(), pd_ctrl.sender()).unwrap();

        Ok(D3capController { pg_ctrl, pd_ctrl, mac_names, ip4_names, ip6_names, server_started: false })
    }

    pub fn start_websocket(&mut self, port: u16) -> io::Result<()> {
        if self.server_started {
            println!("server already started");
        } else {
            start_websocket(port, &self.mac_names, &self.pg_ctrl)?;
            self.server_started = true;
        }
        Ok(())
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
