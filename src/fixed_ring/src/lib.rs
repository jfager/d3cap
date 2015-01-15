// Example modified from https://github.com/mozilla/rust/issues/3562#issuecomment-9210203

// Fixed-size ring buffer: when it is at capacity push will drop the oldest element.

#![allow(unstable)]

extern crate "rustc-serialize" as rustc_serialize;

use std::iter::Iterator;
use std::fmt;
use std::fmt::{Show,Formatter};

use rustc_serialize::{Encoder, Encodable};

pub struct FixedRingBuffer<T> {
    buffer: Vec<T>,
    capacity: usize,        // number of elements the buffer is able to hold (can't guarantee that vec capacity is exactly what we set it to)
    size: usize,            // number of elements with legit values in the buffer
    next: usize,            // index at which new elements land
}

impl<T> FixedRingBuffer<T> {
    pub fn new(capacity: usize) -> FixedRingBuffer<T> {
        FixedRingBuffer {
            buffer: Vec::with_capacity(capacity),
            capacity: capacity,
            size: 0,
            next: 0
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn clear(&mut self) {
        self.buffer.truncate(0);
        self.size = 0;
        self.next = 0;
    }

    pub fn iter(&self) -> RingIterator<T> {
        RingIterator { rb: self, i: 0 }
    }

    pub fn push(&mut self, element: T) {
        assert!(self.capacity > 0);

        if self.size < self.capacity {
            self.buffer.push(element);
            self.size += 1;
        } else {
            self.buffer[self.next] = element;
        }
        self.next = (self.next + 1) % self.capacity;
    }
}

impl<T:Encodable> Encodable for FixedRingBuffer<T> {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_seq(self.len(), |s| {
            for (i, e) in self.iter().enumerate() {
                try!(s.emit_seq_elt(i, |s| e.encode(s)));
            }
            Ok(())
        })
    }
}

impl<T> std::ops::Index<usize> for FixedRingBuffer<T> {
    type Output = T;

    fn index(&self, index: &usize) -> &T {
        assert!(*index < self.size);

        if self.size < self.capacity {
            &self.buffer[*index]
        } else {
            &self.buffer[(self.next + *index) % self.capacity]
        }
    }
}

pub struct RingIterator<'s, T:'s> {
    rb: &'s FixedRingBuffer<T>,
    i: usize
}

impl<'s, T> Iterator for RingIterator<'s, T> {
    type Item = &'s T;

    fn next(&mut self) -> Option<&'s T> {
        if self.i < self.rb.size {
            let out = Some(&self.rb[self.i]);
            self.i += 1;
            out
        } else {
            None
        }
    }
}

impl<T: Show> Show for FixedRingBuffer<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        try!(write!(f, "["));
        let mut first = true;
        for e in self.iter() {
            if !first {
                try!(write!(f, ", "));
            }
            first = false;
            try!(e.fmt(f));
        }
        write!(f, "]")
    }
}

#[test]
fn test_basics() {
    // size 0
    let buffer: FixedRingBuffer<i32> = FixedRingBuffer::new(0);    // rust type inference works very well, but not in this case
    assert!(buffer.len() == 0);

    // size 1
    let mut buffer = FixedRingBuffer::new(1);
    assert!(buffer.len() == 0);

    buffer.push(2);
    assert!(buffer.len() == 1);
    assert!(buffer[0] == 2);

    buffer.push(3);
    assert!(buffer.len() == 1);
    assert!(buffer[0] == 3);

    // size 4
    let mut buffer = FixedRingBuffer::new(4);
    assert!(buffer.len() == 0);

    buffer.push(1);
    assert!(buffer.len() == 1);
    assert!(buffer[0] == 1);

    buffer.push(2);
    assert!(buffer.len() == 2);
    assert!(buffer[0] == 1);
    assert!(buffer[1] == 2);

    buffer.push(3);
    assert!(buffer.len() == 3);
    assert!(buffer[0] == 1);
    assert!(buffer[1] == 2);
    assert!(buffer[2] == 3);

    buffer.push(4);
    assert!(buffer.len() == 4);
    assert!(buffer[0] == 1);
    assert!(buffer[1] == 2);
    assert!(buffer[2] == 3);
    assert!(buffer[3] == 4);

    // At this point the elements have wrapped around.
    buffer.push(5);
    assert!(buffer.len() == 4);
    assert!(buffer[3] == 5);

    // But the public API hides this from clients (and the private fields
    // can only be used within this module).
    assert!(buffer[0] == 2);
    assert!(buffer[1] == 3);
    assert!(buffer[2] == 4);
    assert!(buffer[3] == 5);
    assert!(buffer.to_string() == "[2, 3, 4, 5]".to_string());

    // clear
    buffer.clear();
    assert!(buffer.len() == 0);

    buffer.push(2);
    assert!(buffer.len() == 1);
    assert!(buffer[0] == 2);

    buffer.push(3);
    assert!(buffer.len() == 2);
    assert!(buffer[0] == 2);
    assert!(buffer[1] == 3);
}

// Rust uses a lot of functional programming idioms. One that takes some getting
// used to for imperative programmers is an avoidance of loops (loops rely on
// mutation of a loop variable which is not functional style). Instead looping is
// typically done with functions taking closures, the most common of which are:
// each, map, filter, and fold.
#[test]
fn test_functional() {
    let mut buffer: FixedRingBuffer<i32> = FixedRingBuffer::new(4);
    buffer.push(1);
    buffer.push(3);
    buffer.push(5);
    buffer.push(2);

    // each calls a closure with each element
    // it is more functional than an explicit loop, but requires side effects in order to
    // do anything useful (because the closures user's give to each don't return values)
    let mut max = 0;
    for element in buffer.iter() {
        if *element > max {max = *element}    // dereference because each returns elements by reference
    }
    assert!(max == 5);

    let odd: Vec<bool> = buffer.iter().map(|e| {*e & 1 == 1}).collect();
    assert!(odd == vec![true, true, true, false]);

    // filter returns elements for which the closure returns true
    let odd: Vec<i32> = buffer.iter().filter_map(|&e| {
        if e & 1 == 1 { Some(e) } else { None }
    }).collect();
    assert!(odd == vec![1, 3, 5]);

    // fold uses the closure to combine elements together (possibly into a different type)
    // either forwards (foldl) or in reverse (foldr)
    let sum: i32 = buffer.iter().fold(0, |a, &b| a + b);
    assert!(sum == 1 + 3 + 5 + 2);
}
