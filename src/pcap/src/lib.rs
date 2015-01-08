#![crate_type="lib"]

#![feature(plugin)]

#[plugin]
extern crate bindgen;

extern crate libc;

pub mod rustpcap;
