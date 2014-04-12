use std::comm::{channel, Sender, Receiver};
use std::task::{task};

enum MulticastMsg<T> {
    Msg(T),
    MsgDest(Sender<T>)
}

pub struct Multicast<T> {
    tx: Sender<MulticastMsg<T>>
}

impl<T:Send+Clone> Multicast<T> {
    pub fn new() -> Multicast<T> {
        let (tx, rx): (Sender<MulticastMsg<T>>, Receiver<MulticastMsg<T>>) = channel();
        task().named("multicast").spawn(proc() {
            let mut mc_txs = ~[];
            let mut to_remove = ~[];
            loop {
                match rx.recv_opt() {
                    Some(MsgDest(c)) => mc_txs.push(c),
                    Some(Msg(msg)) => {
                        to_remove.truncate(0);
                        for (i, mc_tx) in mc_txs.iter().enumerate() {
                            if !mc_tx.try_send(msg.clone()) {
                                to_remove.push(i);
                            }
                        }
                        if to_remove.len() > 0 {
                            //Walk in reverse to avoid changing indices of
                            //channels to be removed.
                            for i in to_remove.rev_iter() {
                                mc_txs.remove(*i);
                            }
                        }
                    },
                    None => break
                }
            }
        });
        Multicast { tx: tx }
    }

    pub fn get_sender(&self) -> MulticastSender<T> {
        MulticastSender { tx: self.tx.clone() }
    }

    pub fn add_dest_chan(&self, tx: Sender<T>) {
        self.tx.send(MsgDest(tx));
    }
}

pub struct MulticastSender<T> {
    tx: Sender<MulticastMsg<T>>
}

impl<T:Send> Clone for MulticastSender<T> {
    fn clone(&self) -> MulticastSender<T> {
        MulticastSender { tx: self.tx.clone() }
    }
}

impl<T:Send> MulticastSender<T> {
    pub fn send(&self, msg: T) {
        self.tx.send(Msg(msg));
    }
}
