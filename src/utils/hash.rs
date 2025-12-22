#[allow(dead_code)]
pub const fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < buffer.len() {
        let mut c = buffer[i];
        if c >= b'a' && c <= b'z' {
            c -= 0x20;
        }
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

#[macro_export]
macro_rules! dbj2_hash {
    ($s:expr) => {{
        const H: u32 = $crate::utils::hash::dbj2_hash($s);
        H
    }};
}
