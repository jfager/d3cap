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

unsafe fn start_session(dev: *c_char, promisc: bool, monitor: bool, errbuf: &mut [c_char]) -> Option<*pcap_t> {
    let eb = errbuf.as_ptr();
    println!("Promiscuous mode: {}", promisc);
    println!("Monitor mode: {}", monitor);
    let handle = pcap_create(dev, eb);
    if handle == ptr::null() {
        None
    } else {
        //TODO: handle errors
        pcap_set_buffer_size(handle, 65535);
        pcap_set_timeout(handle, 1000);
        pcap_set_promisc(handle, promisc as c_int);

        println!("can set rfmon: {}", pcap_can_set_rfmon(handle));
        if monitor && pcap_can_set_rfmon(handle) == 1 {
            pcap_set_rfmon(handle, monitor as c_int);
        }
        pcap_activate(handle);
        Some(handle)
    }
}

fn do_capture_loop_dev<C>(ctx: ~C, dev: *c_char, promisc: bool, monitor: bool, errbuf: &mut [c_char],
                          handler:extern "C" fn(*u8, *pcap_pkthdr, *u8)) {
    let session = unsafe { start_session(dev, promisc, monitor, errbuf) };
    match session {
        Some(s) => unsafe {
            let dl = pcap_datalink(s);
            println!("Datalink type: {}", dl);
            println!("Starting capture loop on dev {}", str::raw::from_c_str(dev));

            pcap_loop(s, -1, handler, cast::transmute(ptr::to_unsafe_ptr(ctx)));
        },
        None => unsafe {
            println!("Couldn't open device {}: {:?}\n", str::raw::from_c_str(dev), errbuf);
        }
    }
}

type pcap_handler = extern "C" fn(*u8, *pcap_pkthdr, *u8);

pub fn capture_loop_dev<C>(dev: &str, promisc: bool, monitor: bool, ctx: ~C, handler: pcap_handler) {
    let mut errbuf = vec::with_capacity(256);
    let c_dev = unsafe { dev.to_c_str().unwrap() };
    do_capture_loop_dev(ctx, c_dev, promisc, monitor, errbuf, handler);
}

pub fn capture_loop<C>(ctx: ~C, promisc: bool, monitor: bool, handler: pcap_handler) {
    let mut errbuf = vec::with_capacity(256);
    let dev = unsafe { get_device(errbuf) };
    match dev {
        Some(d) => do_capture_loop_dev(ctx, d, promisc, monitor, errbuf, handler),
        None => fail!("No device available")
    }
}
