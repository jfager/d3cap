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

unsafe fn start_session(dev: *c_char, errbuf: &mut [c_char]) -> Option<*pcap_t> {
    let eb = errbuf.as_ptr();
    let handle = pcap_open_live(dev, 65535, 0, 1000, eb);
    if handle == ptr::null() {
        None
    } else {
        Some(handle)
    }
}

fn do_capture_loop_dev<C>(ctx: ~C, dev: *c_char, errbuf: &mut [c_char],
                          handler:extern "C" fn(*u8, *pcap_pkthdr, *u8)) {
    let session = unsafe { start_session(dev, errbuf) };
    match session {
        Some(s) => unsafe {
            println!("Starting capture loop on dev {}", str::raw::from_c_str(dev));
            pcap_loop(s, -1, handler, cast::transmute(ptr::to_unsafe_ptr(ctx)));
        },
        None => unsafe {
            println!("Couldn't open device {}: {:?}\n", str::raw::from_c_str(dev), errbuf);
        }
    }
}

pub fn capture_loop_dev<C>(dev: &str, ctx: ~C, handler: extern "C" fn(*u8, *pcap_pkthdr, *u8)) {
    let mut errbuf = vec::with_capacity(256);
    let c_dev = unsafe { dev.to_c_str().unwrap() };
    do_capture_loop_dev(ctx, c_dev, errbuf, handler);
}

pub fn capture_loop<C>(ctx: ~C, handler: extern "C" fn(*u8, *pcap_pkthdr, *u8)) {
    let mut errbuf = vec::with_capacity(256);
    let dev = unsafe { get_device(errbuf) };
    match dev {
        Some(d) => do_capture_loop_dev(ctx, d, errbuf, handler),
        None => fail!("No device available")
    }
}