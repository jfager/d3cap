
//TODO: this is dumb and just assumes we're on a little-endian system.
pub fn ntohs(n: u16) -> u16 {
    (n>>8) | (n<<8)
}

pub unsafe fn skip_transmute<T, U>(t: &T) -> &U {
    &*((t as *const T).offset(1) as *const U)
}

pub unsafe fn skip_bytes_transmute<T,U>(t: &T, bytes: int) -> &U {
    &*((t as *const T as *const u8).offset(bytes) as *const U)
}
