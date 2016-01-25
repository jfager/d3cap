use std::collections::hash_map::{self, HashMap};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::hash::{Hash};

use time;

#[derive(Debug)]
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

#[derive(RustcEncodable, Copy, Clone, Debug)]
pub struct PktStats {
    pub count: u64,
    pub size: u64
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

//TODO: derive Encodable manually
#[derive(Clone, Debug)]
pub struct AddrStats<T:Hash+Eq> {
    sent: PktStats,
    sent_to: HashMap<T, PktStats>,
    received: PktStats,
    received_from: HashMap<T, PktStats>
}
impl <'a, T:Hash+Eq+Clone> AddrStats<T> {
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

    pub fn sent_iter(&'a self) -> ASIter<'a, T> {
        ASIter { inner: self.sent_to.iter() }
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

    pub fn recv_iter(&'a self) -> ASIter<'a, T> {
        ASIter { inner: self.received_from.iter() }
    }



    fn get(m: &HashMap<T, PktStats>, addr: &T) -> PktStats {
        match m.get(addr) {
            Some(s) => *s,
            None => PktStats::new()
        }
    }

    fn update(m: &mut HashMap<T, PktStats>, addr: T, size: u32) -> PktStats {
        let stats = match m.entry(addr) {
            Vacant(entry) => entry.insert(PktStats::new()),
            Occupied(entry) => entry.into_mut()
        };
        stats.update(size);
        *stats
    }
}

pub struct ASIter<'a, T:'a> {
    inner: hash_map::Iter<'a, T, PktStats>
}

impl<'a, T: 'a+Hash+Eq+Copy+Clone> Iterator for ASIter<'a, T> {
    type Item = (&'a T, &'a PktStats);

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
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

//TODO: derive Encodable manually
#[derive(Clone, Debug)]
pub struct ProtocolGraph<T:Hash+Eq> {
    stats: PktStats,
    routes: HashMap<T, AddrStats<T>>,
}

impl<'a, T: Hash+Eq+Copy+Clone> ProtocolGraph<T> {
    pub fn new() -> ProtocolGraph<T> {
        ProtocolGraph { stats: PktStats::new(), routes: HashMap::new() }
    }
    pub fn update(&mut self, pkt: &PktMeta<T>) -> RouteStats<T> {
        self.stats.update(pkt.size);

        // TODO: can we do something to avoid all these clones?
        let a_to_b;
        {
            let a = match self.routes.entry(pkt.src) {
                Vacant(entry) => entry.insert(AddrStats::new()),
                Occupied(entry) => entry.into_mut()
            };
            a_to_b = a.update_sent_to(pkt.dst, pkt.size);
        }

        let b_to_a;
        {
            let b = match self.routes.entry(pkt.dst) {
                Vacant(entry) => entry.insert(AddrStats::new()),
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

    pub fn iter(&'a self) -> PGIter<'a, T> {
        PGIter { inner: self.routes.iter() }
    }
}

pub struct PGIter<'a, T:'a+Hash+Eq> {
    inner: hash_map::Iter<'a, T, AddrStats<T>>
}

impl<'a, T: 'a+Hash+Eq+Copy+Clone> Iterator for PGIter<'a, T> {
    type Item = (&'a T, &'a AddrStats<T>);

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}
