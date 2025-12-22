pub unsafe fn find_pattern(start_address: *const u8, len: usize, pattern: &[u8]) -> Option<*mut u8> {
    let data = core::slice::from_raw_parts(start_address, len);
    data.windows(pattern.len()).position(|window| window == pattern)
        .map(|pos| start_address.add(pos) as *mut u8)
}

pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;
    unsafe {
        while *(tmp as *const u8) != 0 { tmp += 1; }
    }
    (tmp - pointer as u64) as _
}