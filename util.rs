
//TODO: this is dumb and just assumes we're on a little-endian system.
pub fn ntohs(n: u16) -> u16 {
    (n>>8) | (n<<8)
}
