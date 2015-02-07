#![feature(collections, core, std_misc, hash, io, os, path, libc)]

extern crate getopts;
extern crate collections;
extern crate time;
extern crate libc;

extern crate toml;
extern crate "rustc-serialize" as rustc_serialize;

extern crate pcap;
extern crate multicast;
extern crate fixed_ring;
extern crate json_serve;

#[macro_use]
#[no_link]
extern crate bitflags;

mod util;
mod ip;
mod ether;
mod dot11;
mod tap;
mod pkt_graph;
mod d3cap;
mod readline;


fn main() {

    use getopts as go;
    use std::{env};
    use d3cap::{D3capConf};

    let interface_opt = "i";
    let file_opt = "f";
    let conf_opt = "c";

    let promisc_flag = "P";
    let monitor_flag = "M";

    let websocket_opt = "websocket";
    let websocket_default = "7432";

    let mut opts = go::Options::new();

    opts.optflag("h", "help", "Print this help menu")
        .optopt(interface_opt, "interface", "Network interface to listen on", "interface")
        .optopt(file_opt, "file", "File to load from", "cap_file")
        .optopt(conf_opt, "conf", "Configuration file", "conf_file")
        .optflag(promisc_flag, "promisc", "Turn on promiscuous mode")
        .optflag(monitor_flag, "monitor", "Turn on monitor mode")
        .optflagopt("", websocket_opt, "Run websocket ui server on startup",
                    &format!("port [{}]", websocket_default)[]);

    let matches = match opts.parse(env::args()) {
        Ok(m) => { m }
        Err(f) => { panic!("{}", f) }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage(&opts.short_usage("d3cap")[]));
        return;
    }

    let conf = D3capConf {
        websocket: matches.opt_default(websocket_opt, "7432").map(|p| {
            match p.parse::<u16>() {
                Ok(v) => v,
                _ => panic!("websocket port must be a number")
            }
        }),
        interface: matches.opt_str(interface_opt),
        file: matches.opt_str(file_opt),
        conf: matches.opt_str(conf_opt),
        promisc: matches.opt_present(promisc_flag),
        monitor: matches.opt_present(monitor_flag)
    };

    d3cap::run(conf);
}
