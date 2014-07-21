extern crate std;

use std::comm::{channel, Sender, Receiver};
use std::task::{TaskBuilder};
use std::sync::Arc;

pub enum MulticastMsg<T> {
    MulticastMsg(Arc<T>),
    MulticastMsgDest(Sender<Arc<T>>)
}

pub struct Multicast<T> {
    tx: Sender<MulticastMsg<T>>
}

impl<T:Send+Share> Multicast<T> {
    pub fn spawn() -> Multicast<T> {
        let (tx, rx): (Sender<MulticastMsg<T>>, Receiver<MulticastMsg<T>>) = channel();
        TaskBuilder::new().named("multicast").spawn(proc() {
            let mut mc_txs = Vec::new();
            let mut to_remove = Vec::new();
            loop {
                match rx.recv_opt() {
                    Ok(MulticastMsgDest(c)) => mc_txs.push(c),
                    Ok(MulticastMsg(msg)) => {
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

    pub fn send(&self, msg: MulticastMsg<T>) {
        self.tx.send(msg)
    }

    pub fn clone_sender(&self) -> Sender<MulticastMsg<T>> {
        self.tx.clone()
    }
}
