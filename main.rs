use std::hashmap::HashMap;
use std::{cast,io,ptr,str,task,u8,u16,vec};
use rustpcap::*;
use extra::net_ip::v4::{Ipv4Rep};
use extra::{net,net_tcp,uv};
use extra::comm::DuplexStream;
use rustwebsocket::*;

type Addrs = (~[u8], ~[u8]);

struct OrdAddrs(Addrs);
impl IterBytes for OrdAddrs {
    fn iter_bytes(&self, lsb0: bool, f: std::to_bytes::Cb) -> bool {
        (**self).iter_bytes(lsb0, f)
    }
}
impl Eq for OrdAddrs {
    fn eq(&self, other: &OrdAddrs) -> bool {
        (**self).eq(&**other)
    }
    fn ne(&self, other: &OrdAddrs) -> bool {
        !self.eq(other)
    }
}
impl OrdAddrs {
    fn from(a: ~[u8], b: ~[u8]) -> OrdAddrs {
        if a <= b { OrdAddrs((a, b)) } else { OrdAddrs((b, a)) }
    }
}

type AddrMap = HashMap<~OrdAddrs, ~Chan<~Addrs>>;

struct HudStats {
    id: uint,
    count: u64,
    routes: HashMap<~Addrs, ~RouteStats>
}
impl HudStats {
    fn new(id: uint) -> HudStats {
        HudStats {
            id: id,
            count: 0,
            routes: HashMap::new()
        }
    }
    fn update(&mut self, rte: ~Addrs) {
        self.count += 1;
        let stats = self.routes.find_or_insert_with(rte, |_| ~RouteStats::new());
        stats.update();
    }
    fn spawn(id: uint) -> Chan<~Addrs> {
        let (port, chan) = stream();
        do spawn {
            let mut hs = HudStats::new(id);
            loop {
                let rte = port.recv();
                hs.update(rte);
            }
        }
        chan
    }
}

struct RouteStats {
    count: u64
}
impl RouteStats {
    fn new() -> RouteStats {
        RouteStats { count: 0 }
    }
    fn update(&mut self) {
        self.count += 1;
    }
}

struct HudContext {
    mac: AddrMap,
    ip4: AddrMap,
    ip6: AddrMap,
    out: ~Chan<~str>,
    id_counter: uint
}

fn mk_json(id: uint, t: &str, src: &str, dst: &str) -> ~str {
    fmt!("{\"conn_id\": %u, \"type\": \"%s\", \"src\": \"%s\", \"dst\": \"%s\"}", id, t, src, dst)
}

impl HudContext {

    fn update(id: uint, map: &mut AddrMap, src: ~[u8], dst: ~[u8], onNew: &fn(&[u8],&[u8])) {
        let key = ~OrdAddrs::from(src.clone(), dst.clone());
        let chan = map.find_or_insert_with(key, |k| {
            onNew(k.first(), k.second());
            ~HudStats::spawn(id)
        });
        chan.send(~(src, dst))
    }

    fn updateEthernet(&mut self, eh: &EthernetHeader) -> bool {
        let id = self.id_counter;
        self.id_counter += 1;
        HudContext::update(id, &mut self.mac, eh.src.toVec(), eh.dst.toVec(), |src,dst| {
            self.out.send(mk_json(id, "mac", mac_to_str(src), mac_to_str(dst)));
            //io::println(fmt!("New mac %s, %s", mac_to_str(src), mac_to_str(dst)));
        });
        true
    }

    fn updateIP4(&mut self, ip: &IP4Header) -> bool {
        let id = self.id_counter;
        self.id_counter += 1;
        HudContext::update(id, &mut self.ip4, ip4_to_vec(&ip.src), ip4_to_vec(&ip.dst), |src,dst| {
            self.out.send(mk_json(id, "ip4", ip4_to_str(src), ip4_to_str(dst)));
            //io::println(fmt!("New ip4 %s, %s", ip4_to_str(src), ip4_to_str(dst)));
        });
        false
    }

    fn updateIP6(&mut self, ip: &IP6Header) -> bool {
        let id = self.id_counter;
        self.id_counter += 1;
        HudContext::update(id, &mut self.ip6, ip.src.toVec(), ip.dst.toVec(), |src,dst| {
            self.out.send(mk_json(id, "ip6", ip6_to_str(src), ip6_to_str(dst)));
            //io::println(fmt!("New ip6 %s, %s", ip6_to_str(src), ip6_to_str(dst)));
        });
        false
    }

}

struct HudParser {
    ctx: ~HudContext
}

impl HudParser {
    fn parseEthernet(&mut self, header: &pcap_pkthdr, packet: *u8) {
        if header.caplen < header.len {
            io::println(fmt!("WARN: Capd only [%?] bytes of packet with length [%?]",
                             header.caplen, header.len));
        }
        if header.len > ETHERNET_HEADER_BYTES as u32 {
            unsafe {
                let ehp: *EthernetHeader = cast::transmute(packet);
                let continueParsing = self.ctx.updateEthernet(&*ehp);
                if continueParsing {
                    self.dispatchEthertype((*ehp).typ, packet);
                }
            }
        }
    }

    fn parseIP4(&mut self, header: *IP4Header) {
        unsafe {
            let continueParsing = self.ctx.updateIP4(&*header);
            if continueParsing {
                //io::println("Continue parsing IP4!");
            }
        }
    }

    fn parseIP6(&mut self, header: *IP6Header) {
        unsafe {
            let continueParsing = self.ctx.updateIP6(&*header);
            if continueParsing {
                //io::println("Continue parsing IP6!");
            }
        }
    }

    fn dispatchEthertype(&mut self, typ: u16, packet: *u8) {
        match typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => unsafe {
                let ipp: *IP4Header = cast_offset(packet, ETHERNET_HEADER_BYTES);
                self.parseIP4(ipp);
            },
            ETHERTYPE_IP6 => unsafe {
                let ipp: *IP6Header = cast_offset(packet, ETHERNET_HEADER_BYTES);
                self.parseIP6(ipp);
            },
            ETHERTYPE_802_1X => {
                //io::println("802.1X!");
            },
            x => {
                //io::println(fmt!("Unknown type: %s", u16::to_str_radix(x, 16)));
            }
        }
    }
}



static ETHERNET_MAC_ADDR_BYTES: uint = 6;
static ETHERNET_ETHERTYPE_BYTES: uint = 2;
static ETHERNET_HEADER_BYTES: uint =
    (ETHERNET_MAC_ADDR_BYTES * 2) + ETHERNET_ETHERTYPE_BYTES;

struct MacAddr([u8,..ETHERNET_MAC_ADDR_BYTES]);

impl MacAddr {
    fn toVec(&self) -> ~[u8] {
        return ~[self[0], self[1], self[2], self[3], self[4], self[5]];
    }
}

impl ToStr for MacAddr {
    fn to_str(&self) -> ~str {
        return fmt!("%s:%s:%s:%s:%s:%s",
                    u8::to_str_radix(self[0], 16),
                    u8::to_str_radix(self[1], 16),
                    u8::to_str_radix(self[2], 16),
                    u8::to_str_radix(self[3], 16),
                    u8::to_str_radix(self[4], 16),
                    u8::to_str_radix(self[5], 16)
                   );
    }
}

fn mac_to_str(mac: &[u8]) -> ~str {
    return fmt!("%s:%s:%s:%s:%s:%s",
                u8::to_str_radix(mac[0], 16),
                u8::to_str_radix(mac[1], 16),
                u8::to_str_radix(mac[2], 16),
                u8::to_str_radix(mac[3], 16),
                u8::to_str_radix(mac[4], 16),
                u8::to_str_radix(mac[5], 16)
               );
}

struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    typ: u16
}

static ETHERTYPE_ARP: u16 = 0x0608;
static ETHERTYPE_IP4: u16 = 0x0008;
static ETHERTYPE_IP6: u16 = 0xDD86;
static ETHERTYPE_802_1X: u16 = 0x8E88;

fn ip4_to_str(ip: &[u8]) -> ~str {
    return fmt!("%u.%u.%u.%u",
                ip[0] as uint, ip[1] as uint, ip[2] as uint, ip[3] as uint);
}

fn ip4_to_vec(ip: &Ipv4Rep) -> ~[u8] {
    return ~[ip.a, ip.b, ip.c, ip.d];
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
    src: Ipv4Rep,
    dst: Ipv4Rep,
}

struct IP6Addr([u8,..16]);
impl IP6Addr {
    fn toVec(&self) -> ~[u8] {
        return ~[self[ 0], self[ 1], self[ 2], self[ 3],
                 self[ 4], self[ 5], self[ 6], self[ 7],
                 self[ 8], self[ 9], self[10], self[11],
                 self[12], self[13], self[14], self[15]];
    }
}
impl ToStr for IP6Addr {
    fn to_str(&self) -> ~str {
        let f = u8::to_str_radix;
        return fmt!("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s",
                    f(self[ 0], 16), f(self[ 1], 16),
                    f(self[ 2], 16), f(self[ 3], 16),
                    f(self[ 4], 16), f(self[ 5], 16),
                    f(self[ 6], 16), f(self[ 7], 16),
                    f(self[ 8], 16), f(self[ 9], 16),
                    f(self[10], 16), f(self[11], 16),
                    f(self[12], 16), f(self[13], 16),
                    f(self[14], 16), f(self[15], 16)
                   );
    }
}

fn ip6_to_str(ip6: &[u8]) -> ~str {
    let f = u8::to_str_radix;
    return fmt!("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s",
                f(ip6[ 0], 16), f(ip6[ 1], 16),
                f(ip6[ 2], 16), f(ip6[ 3], 16),
                f(ip6[ 4], 16), f(ip6[ 5], 16),
                f(ip6[ 6], 16), f(ip6[ 7], 16),
                f(ip6[ 8], 16), f(ip6[ 9], 16),
                f(ip6[10], 16), f(ip6[11], 16),
                f(ip6[12], 16), f(ip6[13], 16),
                f(ip6[14], 16), f(ip6[15], 16)
               );
}

struct IP6Header {
    ver_tc_fl: u32,
    len: u16,
    nxthdr: u8,
    hoplim: u8,
    src: IP6Addr,
    dst: IP6Addr
}

unsafe fn cast_offset<T,U>(base: *T, offset: uint) -> U {
    cast::transmute(ptr::offset(base, offset))
}

extern fn handler(args: *u8, header: &pcap_pkthdr, packet: *u8) {
    unsafe {
        let parser: *mut HudParser = cast::transmute(args);
        (&mut *parser).parseEthernet(header, packet);
    }
}

fn websocketWorker(sockb: &net::tcp::TcpSocketBuf, data_po: &Port<~str>) {
    io::println("websocketWorker");
    let handshake = wsParseHandshake(sockb);
    match handshake {
        Some(hs) => sockb.write_str(hs.getAnswer()),
        None => sockb.write_str("HTTP/1.1 404 Not Found\r\n\r\n")
    }

    loop {
        //io::println("Top of worker loop");
        if data_po.peek() {
            let msg = data_po.recv();
            sockb.write(wsMakeFrame(msg.as_bytes(), WS_TEXT_FRAME));
        }
        //io::println("Parsing input frame");
        let (opt_pl, frameType) = wsParseInputFrame(sockb);
        match frameType {
            WS_CLOSING_FRAME => {
                //io::println("Got closing frame");
                sockb.write(wsMakeFrame([], WS_CLOSING_FRAME));
                break;
            }
            _ => {
                //io::println(fmt!("Got frameType %?", frameType));
            }
        }
    }
    io::println("Done with worker");
}

//fn uiServer(conns_ch: Chan<DuplexStream<~str, ~str>>) {
fn uiServer(data_po: Port<~str>) {
    let (accept_po, accept_ch) = stream();
    let (finish_po, finish_ch) = stream();
    do spawn {
        let addr = extra::net_ip::v4::parse_addr("127.0.0.1");
        let port = 8080;
        let backlog = 128;
        let iotask = &uv::global_loop::get();

        do net::tcp::listen(addr, port, backlog, iotask, |_|{}) |conn, kill_ch| {
            io::println("Listen callback");
            let (res_po, res_ch) = stream::<Option<net_tcp::TcpErrData>>();
            accept_ch.send((conn, res_ch));
            io::println("Waiting on res_po");
            match res_po.recv() {
                Some(err_data) => kill_ch.send(Some(err_data)),
                None => () // wait for next connection
            }
        };
        finish_ch.send(());
    }

    do task::spawn_with(data_po) |dp| {
        loop {
            let (conn, res_ch) = accept_po.recv();
            //do spawn {
                let accept_result = net::tcp::accept(conn);
                match accept_result {
                    Err(accept_error) => {
                        res_ch.send(Some(accept_error));
                        // fail?
                    },
                    Ok(sock) => {
                        res_ch.send(None);
                        let buf = net::tcp::socket_buf(sock);
                        //let (conn_a, conn_b) = DuplexStream::<~str, ~str>();
                        //conns_ch.send(conn_a);
                        websocketWorker(&buf, &dp);
                    }
                }
            //} //spawn
        }
    }
    finish_po.recv();
    io::println("uiServer out");
}


fn capture(data_ch: Chan<~str>) {
    let mut errbuf = std::vec::with_capacity(256);
    let ctx = ~HudContext {
        mac: HashMap::new(),
        ip4: HashMap::new(),
        ip6: HashMap::new(),
        out: ~data_ch,
        id_counter: 0
    };
    let parser = ~HudParser {
        ctx: ctx
    };

    let dev = get_device(errbuf);
    match dev {
        Some(d) => {
            unsafe {
                io::println(fmt!("Found device %s", str::raw::from_buf(d)));
            }
            let session = start_session(d, errbuf);
            match session {
                Some(s) => unsafe {
                    io::println(fmt!("Starting pcap_loop"));
                    pcap_loop(s, -1, handler, cast::transmute(ptr::to_unsafe_ptr(parser)));
                },
                None => unsafe {
                    io::println(fmt!("Couldn't open device %s: %?\n",
                                     str::raw::from_buf(d),
                                     errbuf));
                }
            }
        }
        None => io::println("No device available")
    }
}

pub fn run() {
    let (data_po, data_ch) = stream();

    do task::spawn_with(data_po) |po| { uiServer(po); }

    //Spawn on own thread to avoid interfering w/ uiServer
    let mut t = task::task();
    t.sched_mode(task::ManualThreads(1));
    do t.spawn_with(data_ch) |ch| {
        capture(ch);
    }
}