#![crate_type="lib"]

#![feature(std_misc, collections, io)]

extern crate openssl;

extern crate multicast;

extern crate "rustc-serialize" as rustc_serialize;

pub mod uiserver;

mod rustwebsocket;
