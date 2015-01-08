#![feature(old_orphan_check)]

extern crate getopts;
extern crate collections;
extern crate time;
extern crate libc;

extern crate toml;
extern crate "rustc-serialize" as rustc_serialize;

extern crate pcap;
extern crate multicast;
extern crate json_serve;

mod ring;
mod fixed_vec_macros;
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
    use std::{os};
    use d3cap::{D3capConf};

    let interface_opt = "i";
    let file_opt = "f";
    let conf_opt = "c";

    let promisc_flag = "P";
    let monitor_flag = "M";

    let websocket_opt = "websocket";
    let websocket_default = "7432";

    let args: Vec<String> = os::args();

    let opts = vec![
        go::optflag("h", "help", "Print this help menu"),

        go::optopt(interface_opt, "interface", "Network interface to listen on", "interface"),
        go::optopt(file_opt, "file", "File to load from", "cap_file"),
        go::optopt(conf_opt, "conf", "Configuration file", "conf_file"),
        go::optflag(promisc_flag, "promisc", "Turn on promiscuous mode"),
        go::optflag(monitor_flag, "monitor", "Turn on monitor mode"),

        go::optflagopt("", websocket_opt, "Run websocket ui server on startup", format!("port [{}]", websocket_default).as_slice())
    ];

    let matches = match go::getopts(args.tail(), opts.as_slice()) {
        Ok(m) => { m }
        Err(f) => { panic!("{}", f) }
    };

    if matches.opt_present("h") {
        println!("{}", go::usage(go::short_usage(args[0].as_slice(), opts.as_slice()).as_slice(), opts.as_slice()));
        return;
    }

    let conf = D3capConf {
        websocket: matches.opt_default(websocket_opt, "7432").map(|p| {
            p.parse::<u16>().expect("websocket port must be a number")
        }),
        interface: matches.opt_str(interface_opt),
        file: matches.opt_str(file_opt),
        conf: matches.opt_str(conf_opt),
        promisc: matches.opt_present(promisc_flag),
        monitor: matches.opt_present(monitor_flag)
    };

    d3cap::run(conf);
}
