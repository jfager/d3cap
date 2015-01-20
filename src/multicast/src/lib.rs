#![allow(unstable)]

use std::sync::mpsc::{channel, Sender, SendError, Receiver};
use std::thread;
use std::sync::Arc;

#[derive(Clone)]
pub struct Multicast<T:Send+Sync> {
    msg_tx: Sender<Arc<T>>,
    dest_tx: Sender<Sender<Arc<T>>>
}

impl<T:Send+Sync> Multicast<T> {
    pub fn spawn() -> Multicast<T> {
        let (msg_tx, msg_rx): (Sender<Arc<T>>, Receiver<Arc<T>>) = channel();
        let (dest_tx, dest_rx): (Sender<Sender<Arc<T>>>, Receiver<Sender<Arc<T>>>) = channel();
        thread::Builder::new().name("multicast".to_string()).spawn(move || {
            let mut mc_txs = Vec::new();
            let mut to_remove = Vec::new();
            loop {
                select!(
                    dest = dest_rx.recv() => mc_txs.push(dest.unwrap()),
                    msg = msg_rx.recv() => {
                        let m = msg.unwrap();
                        to_remove.truncate(0);
                        for (i, mc_tx) in mc_txs.iter().enumerate() {
                            if mc_tx.send(m.clone()).is_err() {
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
                    }
                )
            }
        });

        Multicast { msg_tx: msg_tx, dest_tx: dest_tx }
    }

    pub fn send(&self, msg: Arc<T>) -> Result<(), SendError<Arc<T>>> {
        self.msg_tx.send(msg)
    }

    pub fn register(&self, dest: Sender<Arc<T>>) -> Result<(), SendError<Sender<Arc<T>>>> {
        self.dest_tx.send(dest)
    }
}
