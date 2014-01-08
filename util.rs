use std::task;
use std::task::TaskBuilder;

pub fn named_task(name: ~str) -> TaskBuilder {
    let mut ui_task = task::task();
    ui_task.name(name);
    ui_task
}
