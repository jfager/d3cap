use std::task;
use std::task::TaskBuilder;

pub fn named_task(name: ~str) -> TaskBuilder {
    let mut ui_task = task::task();
    ui_task.name(name);
    ui_task
}

//TODO: this is dumb and just assumes we're on a little-endian system.
pub fn ntohs(n: u16) -> u16 {
    (n>>8) | (n<<8)
}
