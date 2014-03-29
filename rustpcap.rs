#![link(name="rustpcap", vers="0.0.1")]

use std::libc::{c_char,c_int};
use std::{ptr,slice,str};
use pcap::*;

//TODO: http://www.tcpdump.org/linktypes.html
type DataLinkType = c_int;
pub static DLT_NULL: DataLinkType = 0;
pub static DLT_ETHERNET: DataLinkType = 1;
pub static DLT_IEEE802_11_RADIO: DataLinkType = 127;

pub struct PcapSessionBuilder {
    priv p: *mut pcap_t,
    activated: bool
}

impl PcapSessionBuilder {

    pub fn new_dev(dev: &str) -> PcapSessionBuilder {
        let mut errbuf = slice::with_capacity(256);
        let c_dev = unsafe { dev.to_c_str().unwrap() };
        PcapSessionBuilder::do_new(c_dev, errbuf)
    }

    pub fn new() -> PcapSessionBuilder {
        let mut errbuf = slice::with_capacity(256);
        let dev = unsafe { pcap_lookupdev(errbuf.as_mut_ptr()) };
        if dev.is_null() {
            fail!("No device available");
        }
        println!("Using dev {}", unsafe { str::raw::from_c_str(dev as *c_char) });
        PcapSessionBuilder::do_new(dev as *c_char, errbuf)
    }

    fn do_new(dev: *c_char, errbuf: &mut [c_char]) -> PcapSessionBuilder {
        let p = unsafe { pcap_create(dev, errbuf.as_mut_ptr()) };
        if p.is_null() { fail!("Could not initialize device"); }
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
    p: *mut pcap_t
}

impl PcapSession {
    pub fn datalink(&self) -> DataLinkType {
        unsafe { pcap_datalink(self.p) }
    }

    pub fn list_datalinks(&self) -> ~[i32] {
        unsafe {
            let mut dlt_buf: *mut c_int = ptr::mut_null();
            let sz = pcap_list_datalinks(self.p, &mut dlt_buf);
            let out = slice::raw::from_buf_raw(dlt_buf as *c_int, sz as uint);
            pcap_free_datalinks(dlt_buf);
            out
        }
    }

    //TODO: add a return value indicating success
    pub fn next<T>(&self, f: |&T, u32|) {
        let mut head_ptr: *mut Struct_pcap_pkthdr = ptr::mut_null();
        let mut data_ptr: *u_char = ptr::null();
        let res = unsafe { pcap_next_ex(self.p, &mut head_ptr, &mut data_ptr) };
        match res {
            0 => return, //timed out
            1 => {
                let (t, sz) = unsafe { (&*(data_ptr as *T), (*head_ptr).len) };
                f(t, sz);
            }
            _ => {
                fail!("pcap_next_ex failed with {}, find something better to do than blow up",
                      res);
            }
        }
    }
}
