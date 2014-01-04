use std::{cast,os,ptr,task};
use std::task::TaskBuilder;

pub fn named_task(name: ~str) -> TaskBuilder {
    let mut ui_task = task::task();
    ui_task.name(name);
    ui_task
}

pub unsafe fn transmute_offset<T,U>(base: *T, offset: int) -> U {
    cast::transmute(ptr::offset(base, offset))
}
