use std::ffi::{self, CString};
use std::str;
use libc;

mod raw {
    use libc;

    #[link(name="readline")]
    extern {
        pub fn readline(p: *const libc::c_char) -> *const libc::c_char;
        pub fn add_history(p: *const libc::c_char);
    }
}


pub fn readline(prompt: &str) -> Option<String> {
    let cprmt = prompt.as_bytes();
    let in_buf = cprmt.as_ptr();
    unsafe {
        let raw = raw::readline(in_buf as *const libc::c_char);
        if !raw.is_null() {
            let slice = ffi::c_str_to_bytes(&raw);
            match str::from_utf8(slice).map(|ret| ret.trim()) {
                Ok(a) if !a.is_empty() => {
                    raw::add_history(raw);
                    Some(a.to_string())
                }
                _ => Some("".to_string())
            }
        } else {
            None
        }
    }
}
