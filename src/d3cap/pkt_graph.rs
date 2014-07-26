use std::collections::hashmap::HashMap;
use std::hash::Hash;

use time;

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

#[deriving(Encodable)]
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
//#[deriving(Encodable)]
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
        match m.find(addr) {
            Some(s) => *s,
            None => PktStats::new()
        }
    }

    fn update(m: &mut HashMap<T, PktStats>, addr: T, size: u32) -> PktStats {
        let stats = m.find_or_insert_with(addr, |_| PktStats::new());
        stats.update(size);
        *stats
    }
}

#[deriving(Encodable)]
pub struct SentStats<T> {
    addr: T,
    sent: PktStats
}

#[deriving(Encodable)]
pub struct RouteStats<T> {
    a: SentStats<T>,
    b: SentStats<T>
}

//TODO: derive manually
//#[deriving(Encodable)]
pub struct ProtocolStats<T> {
    stats: PktStats,
    routes: HashMap<T, AddrStats<T>>,
}

impl<'a, T: Hash+Eq+Copy> ProtocolStats<T> {
    pub fn new() -> ProtocolStats<T> {
        //FIXME:  this is the map that's hitting https://github.com/mozilla/rust/issues/11102
        ProtocolStats { stats: PktStats::new(), routes: HashMap::new() }
    }
    pub fn update(&mut self, pkt: &PktMeta<T>) -> RouteStats<T> {
        self.stats.update(pkt.size);

        // TODO: can we do something to avoid all these clones?
        let a_to_b;
        {
            let a = self.routes.find_or_insert_with(pkt.src, |_| AddrStats::new());
            a_to_b = a.update_sent_to(pkt.dst, pkt.size);
        }

        let b_to_a;
        {
            let b = self.routes.find_or_insert_with(pkt.dst, |_| AddrStats::new());
            b.update_received_from(pkt.src, pkt.size);
            b_to_a = b.get_sent_to(&pkt.src);
        }

        RouteStats {
            a: SentStats { addr: pkt.src, sent: a_to_b },
            b: SentStats { addr: pkt.dst, sent: b_to_a }
        }
    }
}
