use std::comm::{channel, Sender, Receiver};
use std::thread;
use std::sync::Arc;

#[deriving(Clone)]
pub enum Mc<T:Send+Sync> {
    Msg(Arc<T>),
    MsgDest(Sender<Arc<T>>)
}

pub struct Multicast<T:Send+Sync> {
    tx: Sender<Mc<T>>
}

impl<T:Send+Sync> Multicast<T> {
    pub fn spawn() -> Multicast<T> {
        let (tx, rx): (Sender<Mc<T>>, Receiver<Mc<T>>) = channel();
        thread::Builder::new().name("multicast".to_string()).spawn(move || {
            let mut mc_txs = Vec::new();
            let mut to_remove = Vec::new();
            loop {
                match rx.recv_opt() {
                    Ok(Mc::MsgDest(c)) => mc_txs.push(c),
                    Ok(Mc::Msg(msg)) => {
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
            ()
        }).detach();
        Multicast { tx: tx }
    }

    pub fn send(&self, msg: Arc<T>) {
        self.tx.send(Mc::Msg(msg))
    }

    pub fn register(&self, dest: Sender<Arc<T>>) {
        self.tx.send(Mc::MsgDest(dest))
    }
}

impl<T:Send+Sync> Clone for Multicast<T> {
    fn clone(&self) -> Multicast<T> {
        Multicast { tx: self.tx.clone() }
    }
}
