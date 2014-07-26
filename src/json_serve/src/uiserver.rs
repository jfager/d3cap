use std::comm;
use std::io::{Acceptor,Listener,Stream,BufferedStream,IoResult,IoError};
use std::io::net::tcp::{TcpListener};
use std::task::{TaskBuilder};
use std::collections::HashMap;
use std::sync::Arc;

use serialize::{json, Encodable, Encoder};

use ws = rustwebsocket;

use multicast::{Multicast,MulticastMsg,MulticastMsgDest};

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
                        let res = ws::write_frame(msg.as_bytes(), ws::TextFrame, tcps);
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
                        fail!("Disconnected from client")
                    }
                }
            }
            let (_, frameType) = ws::parse_input_frame(tcps);
            match frameType {
                ws::ClosingFrame |
                ws::ErrorFrame   => {
                    let res = ws::write_frame([], ws::ClosingFrame, tcps);
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

        TaskBuilder::new().named("ui_server").spawn(proc() {
            let mut acceptor = TcpListener::bind("127.0.0.1", port).listen();
            println!("Server listening on port {}", port as uint);

            let mut workercount = 0u;
            for tcp_stream in acceptor.incoming() {
                let (conn_tx, conn_rx) = channel();
                conn_tx.send(welcome_msg.clone());
                json_dest_sender.register(conn_tx);
                TaskBuilder::new().named(format!("websocketWorker_{}", workercount)).spawn(proc() {
                    match tcp_stream {
                        Ok(tcps) => {
                            WebSocketWorker.run(&mut BufferedStream::new(tcps), &conn_rx);
                        }
                        _ => fail!("Could not start websocket worker")
                    }
                });
                workercount += 1;
            }
        });

        UIServer { json_multicast: mc }
    }

    pub fn create_sender<'a, T:Encodable<json::Encoder<'a>,IoError>+Send+Share>(&self) -> Sender<Arc<T>> {
        let (tx, rx) = channel();
        let jb = self.json_multicast.clone();
        TaskBuilder::new().named(format!("routes_ui")).spawn(proc() {
            loop {
                let t: Arc<T> = rx.recv();
                jb.send(Arc::new(json::encode(&*t)));
            }
        });
        tx
    }
}
