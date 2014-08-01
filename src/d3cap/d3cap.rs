use std;
use std::task::{TaskBuilder};
use std::hash::Hash;
use std::collections::hashmap::HashMap;
use std::io::File;
use std::sync::Arc;

use multicast::Multicast;
use json_serve::uiserver::UIServer;

use ring::RingBuffer;
use util::{ntohs, skip_bytes_cast, skip_cast};
use ip::{IP4Addr, IP6Addr, IP4Header, IP6Header};
use ether::{EthernetHeader, MacAddr,
            ETHERTYPE_ARP, ETHERTYPE_IP4, ETHERTYPE_IP6, ETHERTYPE_802_1X};
use dot11;
use tap;
use pkt_graph::{PktMeta, ProtocolGraph, RouteStats};

use toml;

#[deriving(Encodable)]
struct RouteStatsMsg<T> {
    typ: &'static str,
    route: RouteStats<T>
}

struct ProtocolHandler<T> {
    tx: Sender<PktMeta<T>>,
    route_stats_mcast: Multicast<RouteStatsMsg<T>>
}
impl <T: Hash+Eq+Copy+Send+Share> ProtocolHandler<T> {
    fn spawn(typ: &'static str) -> ProtocolHandler<T> {
        let (tx, rx) = channel();
        let handler = ProtocolHandler {
            tx: tx,
            route_stats_mcast: Multicast::spawn()
        };

        let mc_sender = handler.route_stats_mcast.clone();
        TaskBuilder::new().named(format!("{}_handler", typ)).spawn(proc() {
            let mut stats = ProtocolGraph::new();
            loop {
                let route_stats = stats.update(&rx.recv());
                let route_stats_msg = Arc::new(RouteStatsMsg {
                    typ: typ,
                    route: route_stats
                });
                mc_sender.send(route_stats_msg);
            }
        });

        handler
    }

    fn send(&self, pkt: PktMeta<T>) {
        self.tx.send(pkt);
    }

    fn register_route_stats_listener(&self, tx: Sender<Arc<RouteStatsMsg<T>>>) {
        self.route_stats_mcast.register(tx);
    }
}

struct EthernetCtx {
    mac: ProtocolHandler<MacAddr>,
    ip4: ProtocolHandler<IP4Addr>,
    ip6: ProtocolHandler<IP6Addr>
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
                let ipp: &IP4Header = unsafe { skip_cast(pkt) };
                self.ip4.send(PktMeta::new(ipp.src, ipp.dst, ntohs(ipp.len) as u32));
            },
            ETHERTYPE_IP6 => {
                let ipp: &IP6Header = unsafe { skip_cast(pkt) };
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

struct RadiotapCtx {
    mac: ProtocolHandler<MacAddr>
}

impl RadiotapCtx {
    fn parse(&mut self, pkt: &tap::RadiotapHeader) {
        fn magic<U>(pkt: &tap::RadiotapHeader) -> &U {
            unsafe { skip_bytes_cast(pkt, pkt.it_len as int) }
        }

        let base: &dot11::Dot11BaseHeader = magic(pkt);
        let fc = base.fr_ctrl;
        if fc.protocol_version() != 0 {
            // bogus packet, bail
            return;
        }

        println!("frame_type: {}", fc.frame_type());
        println!("frame_subtype: {:x}", fc.frame_subtype());

        println!("toDS: {}", fc.has_flag(dot11::ToDS));
        println!("fromDS: {}", fc.has_flag(dot11::FromDS));
        println!("protected: {}", fc.has_flag(dot11::ProtectedFrame));

        match fc.frame_type() {
            dot11::Management => {
                println!("Management frame");
                let mgt: &dot11::ManagementFrameHeader = magic(pkt);
            }
            dot11::Control => {
                println!("Control frame");
            }
            dot11::Data => {
                println!("Data frame");
                let data: &dot11::DataFrameHeader = magic(pkt);
                self.mac.send(PktMeta::new(data.addr1, data.addr2, 1)); //TODO: get length
            }
            dot11::Unknown => {
                println!("Unknown frame type");
            }
        }

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
                println!("Unknown header!");
                println!("has tsft? {}", pkt.has_field(tap::TSFT));
                println!("has flags? {}", pkt.has_field(tap::FLAGS));
                println!("has rate? {}", pkt.has_field(tap::RATE));
                println!("has channel? {}", pkt.has_field(tap::CHANNEL));
                println!("has fhss? {}", pkt.has_field(tap::FHSS));
                println!("has antenna_signal? {}", pkt.has_field(tap::ANTENNA_SIGNAL));
                println!("has antenna_noise? {}", pkt.has_field(tap::ANTENNA_NOISE));
                println!("has lock_quality? {}", pkt.has_field(tap::LOCK_QUALITY));
                println!("has tx_attenuation? {}", pkt.has_field(tap::TX_ATTENUATION));
                println!("has db_tx_attenuation? {}", pkt.has_field(tap::DB_TX_ATTENUATION));
                println!("has dbm_tx_power? {}", pkt.has_field(tap::DBM_TX_POWER));
                println!("has antenna? {}", pkt.has_field(tap::ANTENNA));
                println!("has db_antenna_signal? {}", pkt.has_field(tap::DB_ANTENNA_SIGNAL));
                println!("has db_antenna_noise? {}", pkt.has_field(tap::DB_ANTENNA_NOISE));
                println!("has rx_flags? {}", pkt.has_field(tap::RX_FLAGS));
                println!("has mcs? {}", pkt.has_field(tap::MCS));
                println!("has a_mpdu_status? {}", pkt.has_field(tap::A_MPDU_STATUS));
                println!("has vht? {}", pkt.has_field(tap::VHT));
                println!("has more_it_present? {}", pkt.has_field(tap::MORE_IT_PRESENT));
            }
        }
        println!("");
    }
}

pub fn run(conf: D3capConf) {
    use cap = pcap::rustpcap;

    let mut mac_addr_map: HashMap<MacAddr, String> = HashMap::new();

    match conf.conf {
        Some(ref x) => {
            let s = File::open(&Path::new(x.to_string())).read_to_string().unwrap();
            let t = toml::Parser::new(s.as_slice()).parse().unwrap();
            let known_macs = t.find(&"known-macs".to_string()).unwrap().as_table().unwrap();
            for (k, v) in known_macs.iter() {
                let addr = MacAddr::from_string(k.as_slice());
                let alias = v.as_str();
                if addr.is_some() && alias.is_some() {
                    mac_addr_map.insert(addr.unwrap(), alias.unwrap().to_string());
                }
            }
        }
        _ => ()
    }

    let ui = UIServer::spawn(conf.port, &mac_addr_map);

    TaskBuilder::new().named("packet_capture").spawn(proc() {
        let sess = match conf.file {
            Some(ref f) => cap::PcapSession::from_file(f.as_slice()),
            None => {
                let mut sessBuilder = match conf.interface {
                    Some(ref dev) => cap::PcapSessionBuilder::new_dev(dev.as_slice()),
                    None => cap::PcapSessionBuilder::new()
                };

                sessBuilder.buffer_size(65535)
                           .timeout(1000)
                           .promisc(conf.promisc)
                           .rfmon(conf.monitor)
                           .activate()
            }
        };

        println!("Starting capture loop");
        println!("Available datalink types: {}", sess.list_datalinks());

        match sess.datalink() {
            cap::DLT_ETHERNET => {
                let mut ctx = EthernetCtx {
                    mac: ProtocolHandler::spawn("mac"),
                    ip4: ProtocolHandler::spawn("ip4"),
                    ip6: ProtocolHandler::spawn("ip6")
                };

                ctx.mac.register_route_stats_listener(ui.create_sender());
                ctx.ip4.register_route_stats_listener(ui.create_sender());
                ctx.ip6.register_route_stats_listener(ui.create_sender());

                //FIXME: lame workaround for https://github.com/mozilla/rust/issues/11102
                std::io::timer::sleep(1000);
                loop { sess.next(|t,sz| ctx.parse(t, sz)); }
            },
            cap::DLT_IEEE802_11_RADIO => {
                let mut ctx = RadiotapCtx {
                    mac: ProtocolHandler::spawn("mac"),
                };
                ctx.mac.register_route_stats_listener(ui.create_sender());

                std::io::timer::sleep(1000);
                loop {
                    sess.next(|t,_| ctx.parse(t));
                }
            },
            x => fail!("unsupported datalink type: {}", x)
        }
        //unsafe { std::intrinsics::abort(); }
    });
}

pub struct D3capConf {
    pub port: u16,
    pub interface: Option<String>,
    pub file: Option<String>,
    pub conf: Option<String>,
    pub promisc: bool,
    pub monitor: bool
}
