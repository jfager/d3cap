use std::comm;
use std::io::{io_error,Acceptor,Listener,Stream,BufferedStream};
use std::io::net::tcp::{TcpListener};
use std::io::net::ip::{Ipv4Addr,SocketAddr};

use rustwebsocket::*;
use util::{named_task};

use multicast::Multicast;

fn websocketWorker<S: Stream>(tcps: &mut BufferedStream<S>, data_po: &Port<~str>) {
    println!("websocketWorker");
    let handshake = wsParseHandshake(tcps);
    match handshake {
        Some(hs) => {
            let rsp = hs.getAnswer();
            tcps.write(rsp.as_bytes());
            tcps.flush();
        }
        None => tcps.write("HTTP/1.1 404 Not Found\r\n\r\n".as_bytes())
    }

    io_error::cond.trap(|_| ()).inside(|| {
        loop {
            let mut counter = 0;
            loop {
                match data_po.try_recv() {
                    comm::Data(msg) => {
                        tcps.write(wsMakeFrame(msg.as_bytes(), WS_TEXT_FRAME));
                        tcps.flush();
                        if counter < 100 {
                            counter += 1;
                        } else {
                            break
                        }
                    },
                    comm::Empty => {
                        break
                    },
                    comm::Disconnected => {
                        fail!("Disconnected from client")
                    }
                }
            }
            let (_, frameType) = wsParseInputFrame(tcps);
            match frameType {
                WS_CLOSING_FRAME |
                WS_ERROR_FRAME   => {
                    tcps.write(wsMakeFrame([], WS_CLOSING_FRAME));
                    tcps.flush();
                    break;
                }
                _ => ()
            }
        }
    });
    println!("Done with worker");
}

pub fn uiServer(mc: Multicast<~str>, port: u16) {
    let addr = SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: port };
    let listener = TcpListener::bind(addr);
    let mut acceptor = listener.listen();
    println!("Server listening on port {}", port as uint);

    let mut workercount = 0;
    for tcp_stream in acceptor.incoming() {
        let (conn_po, conn_ch) = Chan::new();
        mc.add_dest_chan(conn_ch);
        do named_task(format!("websocketWorker_{}", workercount)).spawn {
            match tcp_stream {
                Some(tcps) => websocketWorker(&mut BufferedStream::new(tcps), &conn_po),
                None => fail!("Could not start websocket worker")
            }
        }
        workercount += 1;
    }
}
