use std::comm::SharedChan;

enum MulticastMsg<T> {
    Msg(T),
    MsgDest(Chan<T>)
}

pub struct Multicast<T> {
    priv ch: SharedChan<MulticastMsg<T>>
}

impl<T:Send+Clone> Multicast<T> {
    pub fn new() -> Multicast<T> {
        let (po, ch): (Port<MulticastMsg<T>>, SharedChan<MulticastMsg<T>>) = SharedChan::new();
        do spawn {
            let mut mc_chans: ~[Chan<T>] = ~[];
            loop {
                match po.recv_opt() {
                    Some(Msg(msg)) => for mc_chan in mc_chans.iter() { mc_chan.send(msg.clone()) },
                    Some(MsgDest(c)) => mc_chans.push(c),
                    None => break
                }
            }
        }
        Multicast { ch: ch }
    }

    pub fn get_chan(&self) -> MulticastChan<T> {
        MulticastChan { ch: self.ch.clone() }
    }

    pub fn add_dest_chan(&self, chan: Chan<T>) {
        self.ch.send(MsgDest(chan));
    }
}

pub struct MulticastChan<T> {
    priv ch: SharedChan<MulticastMsg<T>>
}

impl<T:Send> Clone for MulticastChan<T> {
    fn clone(&self) -> MulticastChan<T> {
        MulticastChan { ch: self.ch.clone() }
    }
}

impl<T:Send> MulticastChan<T> {
    pub fn send(&self, msg: T) {
        self.ch.send(Msg(msg));
    }
}
