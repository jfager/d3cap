use std::comm::SharedChan;
use std::task;

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
        let mut t = task::task();
        t.name("multicast");
        do t.spawn {
            let mut mc_chans = ~[];
            let mut to_remove = ~[];
            loop {
                match po.recv_opt() {
                    Some(MsgDest(c)) => mc_chans.push(c),
                    Some(Msg(msg)) => {
                        to_remove.truncate(0);
                        for (i, mc_chan) in mc_chans.iter().enumerate() {
                            if !mc_chan.try_send(msg.clone()) {
                                to_remove.push(i);
                            }
                        }
                        if to_remove.len() > 0 {
                            //Walk in reverse to avoid changing indices of
                            //channels to be removed.
                            for i in to_remove.rev_iter() {
                                mc_chans.remove(*i);
                            }
                        }
                    },
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
