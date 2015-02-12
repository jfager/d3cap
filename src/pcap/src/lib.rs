#![crate_type="lib"]

#![feature(std_misc, collections, libc)]

#![feature(plugin)]

#![plugin(bindgen)]

#[no_link]
extern crate bindgen;

extern crate libc;

pub mod rustpcap;
