use std::comm;
use std::io::{Acceptor,Listener,Stream,BufferedStream};
use std::io::net::tcp::{TcpListener};
use std::io::net::ip::{Ipv4Addr,SocketAddr};
use std::task::{TaskBuilder};

use ws = rustwebsocket;

use multicast::Multicast;

fn websocketWorker<S: Stream>(tcps: &mut BufferedStream<S>, data_po: &Receiver<StrBuf>) {
    println!("websocketWorker");
    let handshake = ws::parseHandshake(tcps);
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
                Ok(msg) => {
                    let res = ws::writeFrame(msg.as_bytes(), ws::TextFrame, tcps);
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
        let (_, frameType) = ws::parseInputFrame(tcps);
        match frameType {
            ws::ClosingFrame |
            ws::ErrorFrame   => {
                let res = ws::writeFrame([], ws::ClosingFrame, tcps);
                if res.is_err() {
                    println!("Error writing closing frame: {}", res);
                }
                break;
            }
            _ => ()
        }
    }
    println!("Done with worker");
}

pub fn uiServer(mc: Multicast<StrBuf>, port: u16) {
    let mut acceptor = TcpListener::bind("127.0.0.1", port).listen();
    println!("Server listening on port {}", port as uint);

    let mut workercount = 0;
    for tcp_stream in acceptor.incoming() {
        let (conn_tx, conn_rx) = channel();
        mc.add_dest_chan(conn_tx);
        TaskBuilder::new().named(format!("websocketWorker_{}", workercount)).spawn(proc() {
            match tcp_stream {
                Ok(tcps) => websocketWorker(&mut BufferedStream::new(tcps), &conn_rx),
                _ => fail!("Could not start websocket worker")
            }
        });
        workercount += 1;
    }
}
