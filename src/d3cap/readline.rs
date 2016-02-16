use std::ffi::{self, CString, CStr};
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

#[derive(Debug)]
#[allow(enum_variant_names)]
pub enum ReadlineError {
    NullInPrompt(ffi::NulError),
    NullOnRead
}

pub fn readline(prompt: &str) -> Result<String, ReadlineError> {
    let cprompt = match CString::new(prompt.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Err(ReadlineError::NullInPrompt(e))
    };

    let in_buf = cprompt.as_ptr();
    unsafe {
        let raw = raw::readline(in_buf as *const libc::c_char);
        if !raw.is_null() {
            let slice = CStr::from_ptr(raw).to_bytes();
            match str::from_utf8(slice).map(|ret| ret.trim()) {
                Ok(a) if !a.is_empty() => {
                    raw::add_history(raw);
                    Ok(a.to_owned())
                }
                _ => Ok("".to_owned())
            }
        } else {
            Err(ReadlineError::NullOnRead)
        }
    }
}
