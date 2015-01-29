use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::old_io::{Acceptor,Listener,Stream,BufferedStream,IoResult};
use std::old_io::net::tcp::{TcpListener};
use std::thread;
use std::sync::Arc;

use rustc_serialize::{json, Encodable};

use rustwebsocket as ws;

use multicast::{Multicast};

#[derive(Copy)]
pub struct WebSocketWorker;

impl WebSocketWorker {
    fn handshake<S: Stream>(&self, tcps: &mut BufferedStream<S>) -> IoResult<()> {
        match ws::parse_handshake(tcps) {
            Some(hs) => {
                try!(tcps.write(hs.get_answer().as_bytes()));
                try!(tcps.flush());
            }
            None => {
                try!(tcps.write("HTTP/1.1 404 Not Found\r\n\r\n".as_bytes()));
            }
        }
        Ok(())
    }

    fn run<S: Stream>(&self, tcps: &mut BufferedStream<S>, data_po: &Receiver<Arc<String>>) -> IoResult<()> {

        try!(self.handshake(tcps));

        loop {
            let mut counter = 0u32;
            loop {
                match data_po.try_recv() {
                    Ok(msg) => {
                        let res = ws::write_frame(msg.as_bytes(), ws::FrameType::Text, tcps);
                        if res.is_err() {
                            println!("Error writing msg frame: {:?}", res);
                            break
                        }
                        if counter < 100 {
                            counter += 1;
                        } else {
                            break
                        }
                    },
                    Err(TryRecvError::Empty) => {
                        break
                    },
                    Err(TryRecvError::Disconnected) => {
                        panic!("Disconnected from client")
                    }
                }
            }
            let (_, frame_type) = ws::parse_input_frame(tcps);
            match frame_type {
                ws::FrameType::Closing |
                ws::FrameType::Error   => {
                    let res = ws::write_frame(&[], ws::FrameType::Closing, tcps);
                    if res.is_err() {
                        println!("Error writing closing frame: {:?}", res);
                    }
                    break;
                }
                _ => ()
            }
        }
        Ok(())
    }
}

pub struct UIServer {
    json_multicast: Multicast<String>, //UIServer -> Workers (json msgs)
}

impl UIServer {
    pub fn spawn<T: Encodable>(port: u16, welcome: &T) -> UIServer {
        let welcome_msg = Arc::new(json::encode(welcome).unwrap());

        let mc = Multicast::spawn();
        let json_dest_sender = mc.clone();

        thread::Builder::new().name("ui_server".to_string()).spawn(move || {
            let mut acceptor = TcpListener::bind(("127.0.0.1", port)).listen();
            println!("Server listening on port {}", port);

            let mut wrkr_cnt = 0u32;
            for tcp_stream in acceptor.incoming() {
                let (conn_tx, conn_rx) = channel();
                conn_tx.send(welcome_msg.clone()).unwrap();
                json_dest_sender.register(conn_tx).unwrap();
                thread::Builder::new().name(format!("websocket_{}", wrkr_cnt)).spawn(move || {
                    let tcps = tcp_stream.unwrap();
                    WebSocketWorker.run(&mut BufferedStream::new(tcps), &conn_rx).unwrap();
                });
                wrkr_cnt += 1;
            }
        });

        UIServer { json_multicast: mc }
    }

    pub fn create_sender<T:Encodable+Send+Sync>(&self) -> Sender<Arc<T>> {
        let (tx, rx) = channel();
        let jb = self.json_multicast.clone();
        thread::Builder::new().name("routes_ui".to_string()).spawn(move || -> () {
            loop {
                let t: Result<Arc<T>, _> = rx.recv();
                match t {
                    Ok(t) => {
                        let j: String = json::encode(&*t).unwrap();
                        jb.send(Arc::new(j));
                    }
                    Err(_) => panic!("oh shit")
                }
            }
        });
        tx
    }
}
