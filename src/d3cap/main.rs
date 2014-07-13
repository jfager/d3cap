#![feature(macro_rules, default_type_params)]

extern crate std;
extern crate openssl;
extern crate getopts;
extern crate serialize;
extern crate collections;
extern crate time;
extern crate pcap;

mod ring;
mod rustwebsocket;
mod multicast;
mod fixed_vec_macros;
mod uiserver;
mod util;
mod ip;
mod ether;
mod dot11;
mod tap;
mod d3cap;

fn main() {
    use go = getopts;
    use std::{os};
    use d3cap::{D3capConf};

    let port_opt = "p";
    let interface_opt = "i";
    let promisc_flag = "P";
    let monitor_flag = "M";

    let args:Vec<String> = os::args().iter()
                                     .map(|x| x.to_string())
                                     .collect();
    let opts = vec![
        go::optopt(port_opt, "port", "Websocket port", ""),
        go::optopt(interface_opt, "interface", "Network interface to listen on", ""),
        go::optflag(promisc_flag, "promisc", "Turn on promiscuous mode"),
        go::optflag(monitor_flag, "monitor", "Turn on monitor mode")
    ];

    let matches = match go::getopts(args.tail(), opts.as_slice()) {
        Ok(m) => { m }
        Err(f) => { fail!("{}", f) }
    };

    let port = matches.opt_str(port_opt).unwrap_or("7432".to_string());
    let port = from_str::<u16>(port.as_slice()).unwrap();

    let conf = D3capConf {
        port: port,
        interface: matches.opt_str(interface_opt),
        promisc: matches.opt_present(promisc_flag),
        monitor: matches.opt_present(monitor_flag)
    };

    d3cap::run(conf);
}
