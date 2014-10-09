#![crate_type="lib"]

#![feature(phase)]

#[phase(plugin)]
extern crate bindgen;

extern crate libc;

pub mod rustpcap;
