use std::comm::SharedChan;

enum MulticastMsg<T> {
    Msg(T),
    MsgDest(Chan<T>)
}

struct Multicast<T> {
    priv ch: SharedChan<MulticastMsg<T>>,
}

impl<T:Send+Clone> Multicast<T> {
    pub fn new() -> Multicast<T> {
        let (po, ch) = stream::<MulticastMsg<T>>();
        do spawn {
            let mut mc_chans: ~[Chan<T>] = ~[];
            loop {
                match po.try_recv() {
                    Some(Msg(msg)) => for mc_chan in mc_chans.iter() { mc_chan.send(msg.clone()) },
                    Some(MsgDest(c)) => mc_chans.push(c),
                    None => break
                }
            }
        }
        Multicast { ch: SharedChan::new(ch) }
    }

    pub fn get_chan(&self) -> MulticastSharedChan<T> {
        MulticastSharedChan { ch: self.ch.clone() }
    }

    pub fn add_dest_chan(&self, chan: Chan<T>) {
        self.ch.send(MsgDest(chan));
    }
}

struct MulticastSharedChan<T> {
    priv ch: SharedChan<MulticastMsg<T>>
}

impl<T:Send> Clone for MulticastSharedChan<T> {
    fn clone(&self) -> MulticastSharedChan<T> {
        MulticastSharedChan { ch: self.ch.clone() }
    }
}

impl<T:Send> GenericChan<T> for MulticastSharedChan<T> {
    fn send(&self, msg: T) {
        self.ch.send(Msg(msg));
    }
}
