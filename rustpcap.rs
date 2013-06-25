#[link(name="rustpcap", vers="0.0.1")];

use std::libc::{c_int,c_ulonglong};
use std::{ptr,vec};

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

#[link_args = "-lpcap"]
pub extern {
    pub fn pcap_lookupdev(errbuf: *u8) -> *u8;
    pub fn pcap_open_live(dev: *u8, snaplen: c_int, promisc: c_int, to_ms: c_int, ebuf: *u8) -> *pcap_t;
    pub fn pcap_next(p: *pcap_t, h: &mut pcap_pkthdr) -> *const u8;
    pub fn pcap_loop(p: *pcap_t, cnt: c_int, callback: *u8, user: *u8);
    pub fn pcap_close(p: *pcap_t);
}

pub fn empty_pkthdr() -> ~pcap_pkthdr {
    ~pcap_pkthdr {
        ts: timeval { tv_sec: 0, tv_usec: 0 },
        caplen: 0,
        len: 0
    }
}

pub fn get_device(errbuf: &mut [u8]) -> Option<*u8> {
    unsafe {
        let dev = pcap_lookupdev(vec::raw::to_ptr(errbuf));
        if dev != ptr::null() {
            return Some(dev);
        } else {
            return None;
        }
    }
}

pub fn start_session(dev: *u8, errbuf: &mut [u8]) -> Option<*pcap_t> {
    unsafe {
        let eb = vec::raw::to_ptr(errbuf);
	    let handle = pcap_open_live(dev, 65535, 0, 1000, eb);
	    if handle == ptr::null() {
            None
	    } else {
            Some(handle)
        }
    }
}