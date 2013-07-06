extern mod std;
extern mod extra;

use std::{cast,io,ptr,str,task,u8};
use std::hashmap::HashMap;
use std::comm::SharedChan;

use extra::{net,net_tcp,uv};
//use extra::comm::DuplexStream;

use rustpcap::*;
use rustwebsocket::*;

type Addrs<T> = (T, T);

#[deriving(Eq, IterBytes)]
struct OrdAddrs<T>(Addrs<T>);
impl <T: Ord+IterBytes> OrdAddrs<T> {
    fn from(a: T, b: T) -> OrdAddrs<T> {
        if a <= b { OrdAddrs((a, b)) } else { OrdAddrs((b, a)) }
    }
}

type AddrChanMap<T> = HashMap<~OrdAddrs<T>, ~Chan<~Addrs<T>>>;

struct ProtocolStats<T> {
    typ: &'static str,
    addrs: AddrChanMap<T>
}
impl <T: Ord+IterBytes+Eq+Clone+Copy+Send+ToStr> ProtocolStats<T> {
    fn new(typ: &'static str) -> ProtocolStats<T> {
        ProtocolStats { typ: typ, addrs: HashMap::new() }
    }
    fn update(&mut self, src: T, dst: T, idgen: &mut IdGen, ch: &SharedChan<~str>) {
        let key = ~OrdAddrs::from(src.clone(), dst.clone());
        let chan = self.addrs.find_or_insert_with(key, |k| {
            let id = idgen.next_id();
            ~AddrStats::spawn(id, self.typ, ch)
        });
        chan.send(~(src, dst))
    }
}

struct AddrStats<T> {
    id: uint,
    typ: &'static str,
    count: u64,
    routes: HashMap<~Addrs<T>, ~RouteStats>,
    out_ch: SharedChan<~str>
}
impl <T: IterBytes+Eq+Clone+Copy+Send+ToStr> AddrStats<T> {
    fn new(id: uint, typ: &'static str, ch: SharedChan<~str>) -> AddrStats<T> {
        AddrStats {
            id: id,
            typ: typ,
            count: 0,
            routes: HashMap::new(),
            out_ch: ch
        }
    }
    fn update(&mut self, rte: ~Addrs<T>) {
        self.count += 1;
        let msg = mk_json(self.id, self.typ, rte.first().to_str(), rte.second().to_str());
        let stats = self.routes.find_or_insert_with(rte, |_| ~RouteStats::new());
        stats.update();
        self.out_ch.send(msg);
    }
    fn spawn(id: uint, typ: &'static str, ch: &SharedChan<~str>) -> Chan<~Addrs<T>> {
        let (port, chan) = stream();
        do task::spawn_with(ch.clone()) |oc| {
            let mut hs = AddrStats::new(id, typ, oc);
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
    mac: ProtocolStats<MacAddr>,
    ip4: ProtocolStats<IP4Addr>,
    ip6: ProtocolStats<IP6Addr>,
    out: ~SharedChan<~str>,
    idgen: IdGen
}

struct IdGen(uint);
impl IdGen {
    fn next_id(&mut self) -> uint {
        let out = (**self);
        (**self) += 1;
        out
    }
}

fn mk_json(id: uint, t: &str, src: &str, dst: &str) -> ~str {
    fmt!("{\"conn_id\": %u, \"type\": \"%s\", \"src\": \"%s\", \"dst\": \"%s\"}", id, t, src, dst)
}

trait HudParser {
    fn parse(&self, ctx: &mut HudContext);
}

struct Packet {
    header: *pcap_pkthdr,
    packet: *u8
}
impl HudParser for Packet {
    fn parse(&self, ctx: &mut HudContext) {
        unsafe {
            if (*self.header).caplen < (*self.header).len {
                io::println(fmt!("WARN: Capd only [%?] bytes of packet with length [%?]",
                                 (*self.header).caplen, (*self.header).len));
            }
            if (*self.header).len > ETHERNET_HEADER_BYTES as u32 {
                let ehp: *EthernetHeader = cast::transmute(self.packet);
                (*ehp).parse(ctx);
                (*ehp).dispatch(self.packet, ctx);
            }
        }
    }
}

macro_rules! fixed_iter_bytes(
    ($t:ty) => (
        impl IterBytes for $t {
            fn iter_bytes(&self, lsb0: bool, f: std::to_bytes::Cb) -> bool {
                self.as_slice().iter_bytes(lsb0, f)
            }
        }
    );
)

macro_rules! fixed_eq(
    ($t:ty) => (
        impl Eq for $t {
            fn eq(&self, other: &$t) -> bool {
                self.as_slice().eq(&other.as_slice())
            }
            fn ne(&self, other: &$t) -> bool {
                !self.eq(other)
            }
        }
    );
)

macro_rules! fixed_ord(
    ($t:ty) => (
        impl Ord for $t {
            fn lt(&self, other: &$t) -> bool {
                self.as_slice().lt(&other.as_slice())
            }
            fn le(&self, other: &$t) -> bool {
                self.lt(other) || self.eq(other)
            }
            fn ge(&self, other: &$t) -> bool {
                !self.lt(other)
            }
            fn gt(&self, other: &$t) -> bool {
                !self.le(other)
            }
        }
    );
)

macro_rules! fixed_clone(
    ($t:ty) => (
        impl Clone for $t {
            fn clone(&self) -> $t {
                *(copy self)
            }
        }
    );
)

static ETHERNET_MAC_ADDR_BYTES: uint = 6;
static ETHERNET_ETHERTYPE_BYTES: uint = 2;
static ETHERNET_HEADER_BYTES: uint =
    (ETHERNET_MAC_ADDR_BYTES * 2) + ETHERNET_ETHERTYPE_BYTES;

struct MacAddr([u8,..ETHERNET_MAC_ADDR_BYTES]);

impl MacAddr {
    fn to_vec(&self) -> ~[u8] {
        return ~[self[0], self[1], self[2], self[3], self[4], self[5]];
    }
}

impl ToStr for MacAddr {
    fn to_str(&self) -> ~str {
        use f = std::u8::to_str_radix;
        return fmt!("%s:%s:%s:%s:%s:%s",
                    f(self[0], 16), f(self[1], 16), f(self[2], 16),
                    f(self[3], 16), f(self[4], 16), f(self[5], 16)
                   );
    }
}

fixed_iter_bytes!(MacAddr)
fixed_eq!(MacAddr)
fixed_ord!(MacAddr)
fixed_clone!(MacAddr)

struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    typ: u16
}

impl HudParser for EthernetHeader {
    fn parse(&self, ctx: &mut HudContext) {
        ctx.mac.update(self.src, self.dst, &mut ctx.idgen, ctx.out);
    }
}

impl EthernetHeader {
    fn dispatch(&self, packet: *u8, ctx: &mut HudContext) {
        match self.typ {
            ETHERTYPE_ARP => {
                //io::println("ARP!");
            },
            ETHERTYPE_IP4 => unsafe {
                let ipp: *IP4Header = cast_offset(packet, ETHERNET_HEADER_BYTES);
                (*ipp).parse(ctx);
            },
            ETHERTYPE_IP6 => unsafe {
                let ipp: *IP6Header = cast_offset(packet, ETHERNET_HEADER_BYTES);
                (*ipp).parse(ctx);
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


static ETHERTYPE_ARP: u16 = 0x0608;
static ETHERTYPE_IP4: u16 = 0x0008;
static ETHERTYPE_IP6: u16 = 0xDD86;
static ETHERTYPE_802_1X: u16 = 0x8E88;

struct IP4Addr([u8,..4]);
impl ToStr for IP4Addr {
    fn to_str(&self) -> ~str {
        fmt!("%u.%u.%u.%u",
             self[0] as uint, self[1] as uint, self[2] as uint, self[3] as uint)
    }
}

fixed_iter_bytes!(IP4Addr)
fixed_eq!(IP4Addr)
fixed_ord!(IP4Addr)
fixed_clone!(IP4Addr)

struct IP4Header {
    ver_ihl: u8,
    dscp_ecn: u8,
    len: u16,
    ident: u16,
    flags_frag: u16,
    ttl: u8,
    proto: u8,
    hchk: u16,
    src: IP4Addr,
    dst: IP4Addr,
}

impl HudParser for IP4Header {
    fn parse(&self, ctx: &mut HudContext) {
        ctx.ip4.update(self.src, self.dst, &mut ctx.idgen, ctx.out);
    }
}

struct IP6Addr([u8,..16]);
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

fixed_iter_bytes!(IP6Addr)
fixed_eq!(IP6Addr)
fixed_ord!(IP6Addr)
fixed_clone!(IP6Addr)

struct IP6Header {
    ver_tc_fl: u32,
    len: u16,
    nxthdr: u8,
    hoplim: u8,
    src: IP6Addr,
    dst: IP6Addr
}
impl HudParser for IP6Header {
    fn parse(&self, ctx: &mut HudContext) {
        ctx.ip6.update(self.src, self.dst, &mut ctx.idgen, ctx.out);
    }
}

unsafe fn cast_offset<T,U>(base: *T, offset: uint) -> U {
    cast::transmute(ptr::offset(base, offset))
}

extern fn handler(args: *u8, header: *pcap_pkthdr, packet: *u8) {
    unsafe {
        let ctx: *mut HudContext = cast::transmute(args);
        let p = Packet { header: header, packet: packet };
        p.parse(&mut *ctx);
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
        let mut counter = 0;
        while data_po.peek() && counter < 100 {
            let msg = data_po.recv();
            sockb.write(wsMakeFrame(msg.as_bytes(), WS_TEXT_FRAME));
            counter += 1;
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


fn capture(data_ch: SharedChan<~str>) {
    let mut errbuf = std::vec::with_capacity(256);
    let ctx = ~HudContext {
        mac: ProtocolStats::new("mac"),
        ip4: ProtocolStats::new("ip4"),
        ip6: ProtocolStats::new("ip6"),
        out: ~data_ch,
        idgen: IdGen(0)
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
                    pcap_loop(s, -1, handler, cast::transmute(ptr::to_unsafe_ptr(ctx)));
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
    let data_ch = SharedChan::new(data_ch);

    do task::spawn_with(data_po) |po| { uiServer(po); }

    //Spawn on own thread to avoid interfering w/ uiServer
    let mut t = task::task();
    t.sched_mode(task::ManualThreads(1));
    do t.spawn_with(data_ch) |ch| {
        capture(ch);
    }
}