use std::collections::hash_map::{HashMap};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::hash::Hash;

use time;

#[derive(Show)]
pub struct PktMeta<T> {
    pub src: T,
    pub dst: T,
    pub size: u32,
    pub tm: time::Timespec
}
impl<T> PktMeta<T> {
    pub fn new(src: T, dst: T, size: u32) -> PktMeta<T> {
        PktMeta { src: src, dst: dst, size: size, tm: time::get_time() }
    }
}

#[derive(RustcEncodable, Copy, Clone)]
pub struct PktStats {
    count: u64,
    size: u64
}
impl PktStats {
    pub fn new() -> PktStats {
        PktStats { count: 0, size: 0 }
    }
    pub fn update(&mut self, size: u32) {
        self.count += 1;
        self.size += size as u64;
    }
}

//TODO: derive this manually
//#[derive(Encodable)]
pub struct AddrStats<T> {
    sent: PktStats,
    sent_to: HashMap<T, PktStats>,
    received: PktStats,
    received_from: HashMap<T, PktStats>
}
impl <T:Hash+Eq> AddrStats<T> {
    pub fn new() -> AddrStats<T> {
        AddrStats { sent: PktStats::new(), sent_to: HashMap::new(),
                    received: PktStats::new(), received_from: HashMap::new() }
    }


    pub fn update_sent_to(&mut self, to: T, size: u32) -> PktStats {
        self.sent.update(size);
        AddrStats::update(&mut self.sent_to, to, size)
    }

    pub fn get_sent(&self) -> PktStats {
        self.sent
    }

    pub fn get_sent_to(&self, to: &T) -> PktStats {
        AddrStats::get(&self.sent_to, to)
    }


    pub fn update_received_from(&mut self, from: T, size: u32) -> PktStats {
        self.received.update(size);
        AddrStats::update(&mut self.received_from, from, size)
    }

    pub fn get_received(&self) -> PktStats {
        self.received
    }

    pub fn get_received_from(&self, from: &T) -> PktStats {
        AddrStats::get(&self.received_from, from)
    }


    fn get(m: &HashMap<T, PktStats>, addr: &T) -> PktStats {
        match m.get(addr) {
            Some(s) => *s,
            None => PktStats::new()
        }
    }

    fn update(m: &mut HashMap<T, PktStats>, addr: T, size: u32) -> PktStats {
        let stats = match m.entry(addr) {
            Vacant(entry) => entry.set(PktStats::new()),
            Occupied(entry) => entry.into_mut()
        };
        stats.update(size);
        *stats
    }
}

#[derive(RustcEncodable, Clone)]
pub struct SentStats<T> {
    addr: T,
    sent: PktStats
}

#[derive(RustcEncodable, Clone)]
pub struct RouteStats<T> {
    a: SentStats<T>,
    b: SentStats<T>
}

//TODO: derive manually
//#[derive(Encodable)]
pub struct ProtocolGraph<T> {
    stats: PktStats,
    routes: HashMap<T, AddrStats<T>>,
}

impl<'a, T: Hash+Eq+Copy> ProtocolGraph<T> {
    pub fn new() -> ProtocolGraph<T> {
        ProtocolGraph { stats: PktStats::new(), routes: HashMap::new() }
    }
    pub fn update(&mut self, pkt: &PktMeta<T>) -> RouteStats<T> {
        self.stats.update(pkt.size);

        // TODO: can we do something to avoid all these clones?
        let a_to_b;
        {
            let a = match self.routes.entry(pkt.src) {
                Vacant(entry) => entry.set(AddrStats::new()),
                Occupied(entry) => entry.into_mut()
            };
            a_to_b = a.update_sent_to(pkt.dst, pkt.size);
        }

        let b_to_a;
        {
            let b = match self.routes.entry(pkt.dst) {
                Vacant(entry) => entry.set(AddrStats::new()),
                Occupied(entry) => entry.into_mut()
            };
            b.update_received_from(pkt.src, pkt.size);
            b_to_a = b.get_sent_to(&pkt.src);
        }

        RouteStats {
            a: SentStats { addr: pkt.src, sent: a_to_b },
            b: SentStats { addr: pkt.dst, sent: b_to_a }
        }
    }

    pub fn get_route_stats(&self, a: &T, b: &T) -> Option<RouteStats<T>> {
        let a_opt = self.routes.get(a);
        let b_opt = self.routes.get(b);
        match (a_opt, b_opt) {
            (Some(a_), Some(b_)) => Some(RouteStats {
                a: SentStats { addr: *a, sent: a_.get_sent_to(b) },
                b: SentStats { addr: *b, sent: b_.get_sent_to(a) }
            }),
            _ => None
        }
    }

    pub fn get_addr_stats(&self, addr: &T) -> Option<&AddrStats<T>> {
        self.routes.get(addr)
    }
}
