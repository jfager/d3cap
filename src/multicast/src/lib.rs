use std::comm::{channel, Sender, Receiver};
use std::task::{TaskBuilder};
use std::sync::Arc;

pub enum MulticastMsg<T> {
    McMsg(Arc<T>),
    McMsgDest(Sender<Arc<T>>)
}

pub struct Multicast<T> {
    tx: Sender<MulticastMsg<T>>
}

impl<T:Send+Sync> Multicast<T> {
    pub fn spawn() -> Multicast<T> {
        let (tx, rx): (Sender<MulticastMsg<T>>, Receiver<MulticastMsg<T>>) = channel();
        TaskBuilder::new().named("multicast").spawn(proc() {
            let mut mc_txs = Vec::new();
            let mut to_remove = Vec::new();
            loop {
                match rx.recv_opt() {
                    Ok(McMsgDest(c)) => mc_txs.push(c),
                    Ok(McMsg(msg)) => {
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

    pub fn send(&self, msg: Arc<T>) {
        self.tx.send(McMsg(msg))
    }

    pub fn register(&self, dest: Sender<Arc<T>>) {
        self.tx.send(McMsgDest(dest))
    }
}

impl<T:Send> Clone for Multicast<T> {
    fn clone(&self) -> Multicast<T> {
        Multicast { tx: self.tx.clone() }
    }
}
