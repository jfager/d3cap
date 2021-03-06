use std::iter;
use std::collections::hash_map::{Entry, HashMap};
use std::hash::{Hash};
use std::fmt::{Display};
use std::thread::{self, JoinHandle};
use std::io::{self};

use d3cap::{D3capController, ProtocolHandler, PhysDataController};
use ether::{MacAddr};
use ip::{AsStdIpAddr};

use readline::readline;

trait TransAddr<T> {
    fn trans(&mut self, addr: &T) -> String;
}

impl TransAddr<MacAddr> for HashMap<MacAddr, String> {
    fn trans(&mut self, addr: &MacAddr) -> String {
        match self.get(addr) {
            Some(v) => v.clone(),
            None => addr.to_string()
        }
    }
}

impl<T:AsStdIpAddr+Eq+Hash+Display+Clone> TransAddr<T> for HashMap<T, String> {
    fn trans(&mut self, addr: &T) -> String {
        let k = addr.clone();
        match self.entry(k) {
            Entry::Occupied(e) => e.get().clone(),
            Entry::Vacant(e) => {
                let _a = addr.as_std_ip();
                let n = addr.to_string();
                // let n = match net::lookup_addr(&a) {
                //     Ok(name) => name,
                //     _ => addr.to_string()
                // };
                let out = n.clone();
                e.insert(n);
                out
            }
        }
    }
}

#[derive(Debug)]
enum CliErr {
    IoError(io::Error)
}

impl From<io::Error> for CliErr {
    fn from(e: io::Error) -> CliErr {
        CliErr::IoError(e)
    }
}

type CliFn = (&'static str, Box<FnMut(Vec<&str>, &mut D3capController)->Result<(), CliErr>>);

pub fn start_cli(ctrl: D3capController) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name("cli".to_owned()).spawn(move || {
        fn print_ls_addr<A, T>(ph: &ProtocolHandler<A>, t: &mut T)
            where A: Eq+Hash+Copy+Clone+Display+Send+Sync,
                  T: TransAddr<A>
        {
            let graph = ph.graph.read().unwrap();
            let mut list: Vec<_> = graph.iter()
                .flat_map(|(src_addr, astats)| {
                    iter::repeat(src_addr).zip(astats.sent_iter())
                }).collect();

            list.sort_by(|a,b| (a.1).1.count.cmp(&(b.1).1.count).reverse());

            for &(src_addr, (dst_addr, pstats)) in &list {
                println!("{} -> {}: count: {}, size: {}",
                         t.trans(src_addr), t.trans(dst_addr), pstats.count, pstats.size);
            }
        }

        fn print_ls_tap<T:TransAddr<MacAddr>>(pd_ctrl: &PhysDataController, macs: &mut T) {
            let m = pd_ctrl.map.read().unwrap();
            let mut list: Vec<_> = m.iter()
                .filter(|&(_, v)| v.dat.len() > 1).collect();

            list.sort_by(|a, b| a.1.avg_dist().partial_cmp(&b.1.avg_dist()).unwrap());

            for i in &list {
                let (k, v) = *i;
                println!("{:?} [{}, {}, {}]: total: {}, curr_len: {}, dist: {}",
                         k.0,
                         macs.trans(&k.1[0]), macs.trans(&k.1[1]), macs.trans(&k.1[2]),
                         v.count, v.dat.len(), v.avg_dist());
            }
            println!();
        }

        let mut ctrl = ctrl;

        let mut cmds: HashMap<String, CliFn> = HashMap::new();

        cmds.insert("ping".to_owned(),
                    ("ping", Box::new(|_, _| { println!("pong"); Ok(()) })));

        cmds.insert("websocket".to_owned(),
                    ("websocket", Box::new(|cmd, ctrl| {
                        match cmd[..] {
                            [_, port] => {
                                if let Ok(p) = port.parse() {
                                    ctrl.start_websocket(p)?;
                                }
                            },
                            [_] => {
                                ctrl.start_websocket(7432u16)?;
                            }
                            _ => println!("Unknown argument")
                        }
                        Ok(())
                    })));

        cmds.insert("ls".to_owned(),
                    ("ls", Box::new(|cmd, ctrl| {
                        match cmd[1..] {
                            ["mac"] => print_ls_addr(&ctrl.pg_ctrl.mac, &mut ctrl.mac_names),
                            ["ip4"] => print_ls_addr(&ctrl.pg_ctrl.ip4, &mut ctrl.ip4_names),
                            ["ip6"] => print_ls_addr(&ctrl.pg_ctrl.ip6, &mut ctrl.ip6_names),
                            ["tap"] => print_ls_tap(&ctrl.pd_ctrl, &mut ctrl.mac_names),
                            _ => println!("Illegal argument")
                        }
                        Ok(())
                    })));

        let maxlen = cmds.keys().map(|x| x.len()).max().unwrap();

        loop {
            let val = readline("> ").unwrap();
            let full_cmd: Vec<_> = val.split(' ').collect();
            match full_cmd[0] {
                "h" | "help" => {
                    println!("\nAvailable commands are:");
                    for (cmd, &(desc, _)) in &cmds {
                        println!("    {:2$}\t{}", cmd, desc, maxlen);
                    }
                    println!();
                },
                "q" | "quit" | "exit" => break,
                "" => {}
                cmd => match cmds.get_mut(cmd) {
                    Some(&mut (_, ref mut f)) => f(full_cmd, &mut ctrl).unwrap(),
                    None => println!("unknown command")
                }
            }
        }
    })
}
