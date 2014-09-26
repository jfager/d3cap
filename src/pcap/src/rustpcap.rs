#![link(name="rustpcap", vers="0.0.1")]

use libc::{c_char,c_int};
use std::{ptr,str,vec};
use pcap::*;

//TODO: http://www.tcpdump.org/linktypes.html
pub type DataLinkType = c_int;
pub static DLT_NULL: DataLinkType = 0;
pub static DLT_ETHERNET: DataLinkType = 1;
pub static DLT_IEEE802_11_RADIO: DataLinkType = 127;

pub struct PcapSessionBuilder {
    p: *mut pcap_t,
    activated: bool
}

impl PcapSessionBuilder {

    pub fn new_dev(dev: &str) -> PcapSessionBuilder {
        let mut errbuf = Vec::with_capacity(256u);
        let c_dev = unsafe { dev.to_c_str().unwrap() };
        PcapSessionBuilder::do_new(c_dev, errbuf.as_mut_slice())
    }

    pub fn new() -> PcapSessionBuilder {
        let mut errbuf = Vec::with_capacity(256u);
        let dev = unsafe { pcap_lookupdev(errbuf.as_mut_slice().as_mut_ptr()) };
        if dev.is_null() {
            fail!("No device available");
        }
        println!("Using dev {}", unsafe { str::raw::from_c_str(dev as *const c_char) });
        PcapSessionBuilder::do_new(dev as *const c_char, errbuf.as_mut_slice())
    }

    fn do_new(dev: *const c_char, errbuf: &mut [c_char]) -> PcapSessionBuilder {
        let p = unsafe { pcap_create(dev, errbuf.as_mut_ptr()) };
        if p.is_null() { fail!("Could not initialize device"); }
        PcapSessionBuilder { p: p, activated: false }
    }

    pub fn buffer_size(&mut self, sz: i32) -> &mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_buffer_size(self.p, sz); }
        self
    }

    pub fn timeout(&mut self, to: i32) -> &mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_timeout(self.p, to); }
        self
    }

    pub fn promisc(&mut self, promisc: bool) -> &mut PcapSessionBuilder {
        if self.activated { fail!("Session already activated") }
        unsafe { pcap_set_promisc(self.p, promisc as c_int); }
        self
    }

    pub fn rfmon(&mut self, rfmon: bool) -> &mut PcapSessionBuilder {
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

pub struct PcapSession {
    p: *mut pcap_t
}

impl PcapSession {
    pub fn from_file(f: &str) -> PcapSession {
        let mut errbuf = Vec::with_capacity(256u);
        unsafe {
            let p = pcap_open_offline(f.to_c_str().unwrap(),
                                      errbuf.as_mut_slice().as_mut_ptr());
            PcapSession { p: p }
        }
    }

    pub fn datalink(&self) -> DataLinkType {
        unsafe { pcap_datalink(self.p) }
    }

    pub fn list_datalinks(&self) -> Vec<i32> {
        unsafe {
            let mut dlt_buf = ptr::null_mut();
            let sz = pcap_list_datalinks(self.p, &mut dlt_buf);
            let out = vec::raw::from_buf(dlt_buf as *const c_int, sz as uint);
            pcap_free_datalinks(dlt_buf);
            out
        }
    }

    //TODO: add a return value for success/failure
    pub fn next<T>(&self, f: |&T, u32|) {
        let mut head_ptr = ptr::null_mut();
        let mut data_ptr = ptr::null();
        let res = unsafe { pcap_next_ex(self.p, &mut head_ptr, &mut data_ptr) };
        match res {
            0 => return, //timed out
            1 => {
                let (t, sz) = unsafe { (&*(data_ptr as *const T), (*head_ptr).len) };
                f(t, sz);
            }
            _ => {
                fail!("pcap_next_ex failed with {}, find something better to do than blow up",
                      res);
            }
        }
    }
}
