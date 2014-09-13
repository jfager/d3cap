use std::c_str;
use libc;

mod raw {
    use libc;

    #[link(name="readline")]
    extern {
        pub fn readline(p: *mut libc::c_char) -> *mut libc::c_char;
        pub fn add_history(p: *mut libc::c_char);
    }
}


pub fn readline(prompt: &str) -> Option<String> {
    let mut cprmt = prompt.to_c_str();
    let in_buf = cprmt.as_mut_ptr();
    unsafe {
        let raw = raw::readline(in_buf);
        if raw.is_not_null() {
            let ret = c_str::CString::new(raw as *const libc::c_char, true);
            match ret.as_str().map(|ret| ret.trim()) {
                Some(a) if !a.is_empty() => {
                    raw::add_history(raw);
                    Some(a.to_string())
                }
                _ => None
            }
        } else {
            None
        }
    }
}
