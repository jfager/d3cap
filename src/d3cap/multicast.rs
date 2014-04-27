use std::comm::{channel, Sender, Receiver};
use std::task::{TaskBuilder};

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
        TaskBuilder::new().named("multicast").spawn(proc() {
            let mut mc_txs = Vec::new();
            let mut to_remove = Vec::new();
            loop {
                match rx.recv_opt() {
                    Ok(MsgDest(c)) => mc_txs.push(c),
                    Ok(Msg(msg)) => {
                        to_remove.truncate(0);
                        for (i, mc_tx) in mc_txs.iter().enumerate() {
                            if mc_tx.send_opt(msg.clone()).is_err() {
                                to_remove.push(i)
                            }
                        }
                        if to_remove.len() > 0 {
                            //Walk in reverse to avoid changing indices of
                            //channels to be removed.
                            for i in to_remove.iter().rev() {
                                mc_txs.remove(*i);
                            }
                        }
                    },
                    Err(_) => break
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
