#![crate_type="lib"]

#![feature(std_misc, collections, libc)]

#![feature(plugin)]

#[plugin]
#[no_link]
extern crate bindgen;

extern crate libc;

pub mod rustpcap;
