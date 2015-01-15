#![crate_type="lib"]
#![allow(unstable)]

extern crate openssl;

extern crate multicast;

extern crate "rustc-serialize" as rustc_serialize;

pub mod uiserver;

mod rustwebsocket;
