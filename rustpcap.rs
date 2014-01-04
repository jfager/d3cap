#[link(name="rustpcap", vers="0.0.1")];

use std::libc::{c_char,c_int,c_ulonglong};
use std::{cast,ptr,str,vec};

pub enum pcap_t {}

pub struct pcap_pkthdr {
    ts: timeval, // time stamp
    caplen: u32, // length of portion present
    len: u32     // length this packet (off wire)
}

pub struct timeval {
    tv_sec: c_ulonglong,
    tv_usec: c_ulonglong
}

#[link(name="pcap")]
extern {
    pub fn pcap_lookupdev(errbuf: *c_char) -> *c_char;
    pub fn pcap_create(source: *c_char, errbuf: *c_char) -> *pcap_t;

    pub fn pcap_set_promisc(p: *pcap_t, promisc: c_int) -> c_int;
    pub fn pcap_can_set_rfmon(p: *pcap_t) -> c_int;
    pub fn pcap_set_rfmon(p: *pcap_t, rfmon: c_int) -> c_int;
    pub fn pcap_set_buffer_size(p: *pcap_t, buffer_size: c_int) -> c_int;
    pub fn pcap_set_timeout(p: *pcap_t, to_ms: c_int) -> c_int;

    pub fn pcap_activate(p: *pcap_t) -> c_int;

    pub fn pcap_datalink(p: *pcap_t) -> c_int;

    pub fn pcap_open_live(dev: *c_char, snaplen: c_int, promisc: c_int, to_ms: c_int, ebuf: *c_char) -> *pcap_t;

    pub fn pcap_next(p: *pcap_t, h: &mut pcap_pkthdr) -> *u8;
    pub fn pcap_loop(p: *pcap_t, cnt: c_int, callback: extern "C" fn(*u8, *pcap_pkthdr, *u8), user: *u8);
    pub fn pcap_close(p: *pcap_t);
}

unsafe fn get_device(errbuf: &mut [c_char]) -> Option<*c_char> {
    let dev = pcap_lookupdev(errbuf.as_ptr());
    if dev != ptr::null() {
        return Some(dev);
    } else {
        return None;
    }
}

type pcap_handler = extern "C" fn(*u8, *pcap_pkthdr, *u8);

//TODO: http://www.tcpdump.org/linktypes.html
type DataLinkType = c_int;
static DLT_NULL: DataLinkType = 0;
static DLT_ETHERNET: DataLinkType = 1;
static DLT_IEEE802_11_RADIO: DataLinkType = 127;

pub struct PcapSessionBuilder {
    priv p: *pcap_t,
    activated: bool
}

impl PcapSessionBuilder {

    pub fn new_dev(dev: &str) -> PcapSessionBuilder {
        let mut errbuf = vec::with_capacity(256);
        let c_dev = unsafe { dev.to_c_str().unwrap() };
        PcapSessionBuilder::do_new(c_dev, errbuf)
    }

    pub fn new() -> PcapSessionBuilder {
        let mut errbuf = vec::with_capacity(256);
        let dev = unsafe { get_device(errbuf) };
        match dev {
            Some(d) => {
                println!("Using dev {}", unsafe { str::raw::from_c_str(d) });
                PcapSessionBuilder::do_new(d, errbuf)
            },
            None => fail!("No device available")
        }
    }

    fn do_new(dev: *c_char, errbuf: &mut [c_char]) -> PcapSessionBuilder {
        let p = unsafe { pcap_create(dev, errbuf.as_ptr()) };
        if p == ptr::null() { fail!("Could not initialize device"); }
        PcapSessionBuilder { p: p, activated: false }
    }

    pub fn buffer_size<'a>(&'a mut self, sz: i32) -> &'a mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_buffer_size(self.p, sz); }
        self
    }

    pub fn timeout<'a>(&'a mut self, to: i32) -> &'a mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_timeout(self.p, to); }
        self
    }

    pub fn promisc<'a>(&'a mut self, promisc: bool) -> &'a mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_promisc(self.p, promisc as c_int); }
        self
    }

    pub fn rfmon<'a>(&'a mut self, rfmon: bool) -> &'a mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_rfmon(self.p, rfmon as c_int); }
        self
    }

    pub fn activate(&mut self) -> PcapSession {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_activate(self.p); }
        self.activated = true;
        PcapSession { p: self.p }
    }
}

struct PcapSession {
    priv p: *pcap_t
}

impl PcapSession {
    pub fn datalink(&self) -> DataLinkType {
        unsafe { pcap_datalink(self.p) }
    }

    pub fn start_loop<C>(&mut self, ctx: ~C, handler: pcap_handler) {
        unsafe { pcap_loop(self.p, -1, handler, cast::transmute(ptr::to_unsafe_ptr(ctx))); }
    }
}
