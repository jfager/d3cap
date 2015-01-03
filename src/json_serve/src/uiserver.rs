use std::comm;
use std::io::{Acceptor,Listener,Stream,BufferedStream,IoResult,IoError};
use std::io::net::tcp::{TcpListener};
use std::thread;
use std::sync::Arc;

use rustc_serialize::{json, Encodable, Encoder};

use rustwebsocket as ws;

use multicast::{Multicast};

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
            let mut counter = 0u;
            loop {
                match data_po.try_recv() {
                    Ok(msg) => {
                        let res = ws::write_frame(msg.as_bytes(), ws::FrameType::Text, tcps);
                        if res.is_err() {
                            println!("Error writing msg frame: {}", res);
                            break
                        }
                        if counter < 100 {
                            counter += 1;
                        } else {
                            break
                        }
                    },
                    Err(comm::Empty) => {
                        break
                    },
                    Err(comm::Disconnected) => {
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
                        println!("Error writing closing frame: {}", res);
                    }
                    break;
                }
                _ => ()
            }
        }
        println!("Done with worker");
        Ok(())
    }
}

pub struct UIServer {
    json_multicast: Multicast<String>, //UIServer -> Workers (json msgs)
}

impl UIServer {
    pub fn spawn<'a, T:Encodable<json::Encoder<'a>,IoError>>(port: u16, welcome: &T) -> UIServer {
        let welcome_msg = Arc::new(json::encode(welcome));

        let mc = Multicast::spawn();
        let json_dest_sender = mc.clone();

        thread::Builder::new().name("ui_server".to_string()).spawn(move || {
            let mut acceptor = TcpListener::bind(("127.0.0.1", port)).listen();
            println!("Server listening on port {}", port as uint);

            let mut wrkr_cnt = 0u;
            for tcp_stream in acceptor.incoming() {
                let (conn_tx, conn_rx) = channel();
                conn_tx.send(welcome_msg.clone());
                json_dest_sender.register(conn_tx);
                thread::Builder::new().name(format!("websocketWorker_{}", wrkr_cnt)).spawn(move || {
                    match tcp_stream {
                        Ok(tcps) => {
                            WebSocketWorker.run(&mut BufferedStream::new(tcps), &conn_rx).unwrap();
                        }
                        _ => panic!("Could not start websocket worker")
                    }
                }).detach();
                wrkr_cnt += 1;
            }
        }).detach();

        UIServer { json_multicast: mc }
    }

    pub fn create_sender<'a, T:Encodable<json::Encoder<'a>,IoError>+Send+Sync>(&self) -> Sender<Arc<T>> {
        let (tx, rx) = channel();
        let jb = self.json_multicast.clone();
        thread::Builder::new().name("routes_ui".to_string()).spawn(move || {
            loop {
                let t: Arc<T> = rx.recv();
                let j: String = json::encode(&*t);
                jb.send(Arc::new(j));
            }
            ()
        }).detach();
        tx
    }
}
