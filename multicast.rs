use std::comm::SharedChan;

enum MulticastMsg<T> {
    Msg(T),
    MsgCb(~fn(&T))
}

struct Multicast<T> {
    priv ch: SharedChan<MulticastMsg<T>>,
}

impl<T:Send+Clone> Multicast<T> {
    pub fn new() -> Multicast<T> {
        let (po, ch) = stream::<MulticastMsg<T>>();
        do spawn {
            let mut cbs: ~[~fn(&T)] = ~[];
            loop {
                match po.try_recv() {
                    Some(Msg(msg)) => for cb in cbs.iter() { (*cb)(&msg) },
                    Some(MsgCb(cb)) => cbs.push(cb),
                    None => break
                }
            }
        }
        Multicast { ch: SharedChan::new(ch) }
    }

    pub fn get_chan(&self) -> MulticastSharedChan<T> {
        MulticastSharedChan { ch: self.ch.clone() }
    }

    pub fn add_handler(&self, cb: ~fn(&T)) {
        self.ch.send(MsgCb(cb));
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