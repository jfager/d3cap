#![crate_type="lib"]

#![feature(core)]

extern crate openssl;
extern crate multicast;
extern crate rustc_serialize;
extern crate byteorder;

pub mod uiserver;

mod rustwebsocket;
