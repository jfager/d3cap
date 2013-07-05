extern mod std;
extern mod extra;

use std::hashmap::HashMap;
use std::{cast,io,ptr,str,task,u8};
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

type AddrMap<T> = HashMap<~OrdAddrs<T>, ~Chan<~Addrs<T>>>;
trait Update<T> {
   fn update(&mut self, src: T, dst: T, onNew: &fn(T,T)->uint);
}
impl <T: Ord+IterBytes+Eq+Copy+Send> Update<T> for AddrMap<T> {
    fn update(&mut self, src: T, dst: T, onNew: &fn(T,T)->uint) {
        let key = ~OrdAddrs::from(copy src, copy dst);
        let chan = self.find_or_insert_with(key, |k| {
            let id = onNew(k.first(), k.second());
            ~HudStats::spawn(id)
        });
        chan.send(~(src, dst))
    }
}

struct HudStats<T> {
    id: uint,
    count: u64,
    routes: HashMap<~Addrs<T>, ~RouteStats>
}
impl <T: IterBytes+Eq+Copy+Send> HudStats<T> {
    fn new(id: uint) -> HudStats<T> {
        HudStats {
            id: id,
            count: 0,
            routes: HashMap::new()
        }
    }
    fn update(&mut self, rte: ~Addrs<T>) {
        self.count += 1;
        let stats = self.routes.find_or_insert_with(rte, |_| ~RouteStats::new());
        stats.update();
    }
    fn spawn(id: uint) -> Chan<~Addrs<T>> {
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
    mac: AddrMap<MacAddr>,
    ip4: AddrMap<IP4Addr>,
    ip6: AddrMap<IP6Addr>,
    out: ~Chan<~str>,
    id_counter: uint
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

struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    typ: u16
}

impl HudParser for EthernetHeader {
    fn parse(&self, ctx: &mut HudContext) {
        ctx.mac.update(self.src, self.dst, |src,dst| {
            let id = ctx.id_counter;
            ctx.id_counter += 1;
            ctx.out.send(mk_json(id, "mac", src.to_str(), dst.to_str()));
            id
        });
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
        ctx.ip4.update(self.src, self.dst, |src,dst| {
            let id = ctx.id_counter;
            ctx.id_counter += 1;
            ctx.out.send(mk_json(id, "ip4", src.to_str(), dst.to_str()));
            id
        });
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
        ctx.ip6.update(self.src, self.dst, |src,dst| {
            let id = ctx.id_counter;
            ctx.id_counter += 1;
            ctx.out.send(mk_json(id, "ip6", src.to_str(), dst.to_str()));
            id
        });
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

    do task::spawn_with(data_po) |po| { uiServer(po); }

    //Spawn on own thread to avoid interfering w/ uiServer
    let mut t = task::task();
    t.sched_mode(task::ManualThreads(1));
    do t.spawn_with(data_ch) |ch| {
        capture(ch);
    }
}