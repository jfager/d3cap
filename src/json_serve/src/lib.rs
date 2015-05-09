#![crate_type="lib"]

#![feature(buf_stream)]

extern crate openssl;
extern crate multicast;
extern crate rustc_serialize;
extern crate byteorder;

pub mod uiserver;

mod rustwebsocket;
