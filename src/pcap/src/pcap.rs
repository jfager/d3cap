use libc::{self,c_char,c_int};
use std::{ptr, slice};
use std::ffi::CString;
use crate::pcapll;

//TODO: http://www.tcpdump.org/linktypes.html
pub type DataLinkType = c_int;
pub const DLT_NULL: DataLinkType = 0;
pub const DLT_ETHERNET: DataLinkType = 1;
pub const DLT_IEEE802_11_RADIO: DataLinkType = 127;

#[derive(Copy,Clone)]
pub struct PcapSessionBuilder {
    p: *mut pcapll::pcap_t,
    activated: bool
}

pub fn list_devices() {
    println!("list_devices")
}

impl PcapSessionBuilder {

    pub fn new_dev(dev: &str) -> Result<PcapSessionBuilder, &'static str> {
        let mut errbuf = Vec::with_capacity(256);
        let c_dev = CString::new(dev.as_bytes()).unwrap();
        PcapSessionBuilder::do_new(c_dev.as_ptr(), errbuf.as_mut_slice())
    }

    pub fn new() -> Result<PcapSessionBuilder, &'static str> {
        let mut errbuf = Vec::with_capacity(256);
        let dev = unsafe { pcapll::pcap_lookupdev(errbuf.as_mut_slice().as_mut_ptr()) };
        if dev.is_null() {
            Err("No device available")
        } else {
            PcapSessionBuilder::do_new(dev as *const c_char, errbuf.as_mut_slice())
        }
    }

    fn do_new(dev: *const c_char, errbuf: &mut [c_char]) -> Result<PcapSessionBuilder, &'static str> {
        let p = unsafe { pcapll::pcap_create(dev, errbuf.as_mut_ptr()) };
        if p.is_null() {
            Err("Could not initialize device")
        } else {
            Ok(PcapSessionBuilder { p, activated: false })
        }
    }

    pub fn buffer_size(&mut self, sz: i32) -> &mut PcapSessionBuilder {
        if self.activated { panic!("Session already activated") }
        unsafe { pcapll::pcap_set_buffer_size(self.p, sz); }
        self
    }

    pub fn timeout(&mut self, to: i32) -> &mut PcapSessionBuilder {
        if self.activated { panic!("Session already activated") }
        unsafe { pcapll::pcap_set_timeout(self.p, to); }
        self
    }

    pub fn promisc(&mut self, promisc: bool) -> &mut PcapSessionBuilder {
        if self.activated { panic!("Session already activated") }
        unsafe { pcapll::pcap_set_promisc(self.p, promisc as c_int); }
        self
    }

    pub fn rfmon(&mut self, rfmon: bool) -> &mut PcapSessionBuilder {
        if self.activated { panic!("Session already activated") }
        unsafe { pcapll::pcap_set_rfmon(self.p, rfmon as c_int); }
        self
    }

    pub fn activate(&mut self) -> PcapSession {
        if self.activated { panic!("Session already activated") }
        unsafe {
            let res = pcapll::pcap_activate(self.p);
            if res != 0 {
                panic!("Could not activate pcap session: {}", res);
            }
        }
        self.activated = true;
        PcapSession { p: self.p }
    }
}

#[derive(Copy,Clone)]
pub struct PcapSession {
    p: *mut pcapll::pcap_t
}

impl PcapSession {
    pub fn from_file(f: &str) -> PcapSession {
        let mut errbuf = Vec::with_capacity(256);
        unsafe {
            let cs = CString::new(f.as_bytes()).unwrap();
            let p = pcapll::pcap_open_offline(cs.as_ptr(), errbuf.as_mut_slice().as_mut_ptr());
            PcapSession { p }
        }
    }

    pub fn datalink(self) -> DataLinkType {
        unsafe { pcapll::pcap_datalink(self.p) }
    }

    pub fn list_datalinks(self) -> Vec<i32> {
        unsafe {
            let mut dlt_buf = ptr::null_mut();
            let sz = pcapll::pcap_list_datalinks(self.p, &mut dlt_buf);
            let out = slice::from_raw_parts(dlt_buf as *const c_int, sz as usize).to_vec();
            pcapll::pcap_free_datalinks(dlt_buf);
            out
        }
    }

    //TODO: add a return value for success/failure
    pub fn next<F>(self, mut f: F) where F: FnMut(&PcapData) {
        let mut head_ptr = ptr::null_mut();
        let mut data_ptr = ptr::null();
        let res = unsafe { pcapll::pcap_next_ex(self.p, &mut head_ptr, &mut data_ptr) };
        match res {
            0 => return, //timed out
            1 => {
                let p = PcapData { hdr: head_ptr, dat: data_ptr };
                f(&p);
            }
            _ => {
                panic!("pcap_next_ex panicked with {}, find something better to do than blow up",
                       res);
            }
        }
    }
}


pub struct PcapTimeval(libc::timeval);

impl PcapTimeval {
    pub fn sec(&self) -> i64 {
        self.0.tv_sec
    }

    pub fn usec(&self) -> i32 {
        self.0.tv_usec
    }
}

pub struct PcapData {
    hdr: *mut pcapll::Struct_pcap_pkthdr,
    dat: *const u8
}

impl PcapData {
    pub fn len(&self) -> u32 {
        unsafe { (*self.hdr).len }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn caplen(&self) -> u32 {
        unsafe { (*self.hdr).caplen }
    }

    pub fn ts(&self) -> PcapTimeval {
        unsafe { PcapTimeval((*self.hdr).ts) }
    }

    pub fn pkt_ptr(&self) -> *const u8 {
        self.dat
    }
}

pub struct PcapDumper {
    p: *mut pcapll::Struct_pcap_dumper
}

impl PcapDumper {
    pub fn new(sess: PcapSession, path: &str) -> PcapDumper {
        unsafe {
            let cs = CString::new(path.as_bytes()).unwrap();
            let p = pcapll::pcap_dump_open(sess.p, cs.as_ptr());
            PcapDumper { p }
        }
    }

    pub fn dump(&mut self, data: &PcapData) {
        unsafe {
            pcapll::pcap_dump(self.p as *mut u8, data.hdr, data.dat);
        }
    }
}

impl Drop for PcapDumper {
    fn drop(&mut self) {
        unsafe {
            pcapll::pcap_dump_close(self.p);
        }
    }
}
