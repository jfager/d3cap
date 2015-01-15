#![crate_type="lib"]
#![allow(unstable)]

#![feature(plugin)]

#[plugin]
#[no_link]
extern crate bindgen;

extern crate libc;

pub mod rustpcap;
