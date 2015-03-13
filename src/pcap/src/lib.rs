#![crate_type="lib"]

#![feature(collections, libc)]

#![feature(plugin)]

#![plugin(bindgen)]

#[no_link]
extern crate bindgen;

extern crate libc;

pub mod rustpcap;
