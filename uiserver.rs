use std::comm;
use std::io::{Acceptor,Listener,Stream,BufferedStream};
use std::io::net::tcp::{TcpListener};
use std::io::net::ip::{Ipv4Addr,SocketAddr};
use std::task::{task};

use rustwebsocket::*;

use multicast::Multicast;

fn websocketWorker<S: Stream>(tcps: &mut BufferedStream<S>, data_po: &Port<~str>) {
    println!("websocketWorker");
    let handshake = wsParseHandshake(tcps);
    match handshake {
        Some(hs) => {
            match tcps.write(hs.getAnswer().as_bytes()) {
                Ok(_) => match tcps.flush() {
                    Ok(_) => (),
                    _ => fail!("Couldn't flush")
                },
                _ => fail!("Couldn't write bytes")
            }
        }
        None => match tcps.write("HTTP/1.1 404 Not Found\r\n\r\n".as_bytes()) {
            Ok(_) => (),
            _ => fail!("Couldn't write Not Found error")
        }
    }

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
    println!("Done with worker");
}

pub fn uiServer(mc: Multicast<~str>, port: u16) {
    let addr = SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: port };
    let mut acceptor = TcpListener::bind(addr).listen();
    println!("Server listening on port {}", port as uint);

    let mut workercount = 0;
    for tcp_stream in acceptor.incoming() {
        let (conn_po, conn_ch) = Chan::new();
        mc.add_dest_chan(conn_ch);
        task().named(format!("websocketWorker_{}", workercount)).spawn(proc() {
            match tcp_stream {
                Ok(tcps) => websocketWorker(&mut BufferedStream::new(tcps), &conn_po),
                _ => fail!("Could not start websocket worker")
            }
        });
        workercount += 1;
    }
}
