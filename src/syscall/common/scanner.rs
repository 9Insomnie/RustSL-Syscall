pub unsafe fn find_pattern(
    start_address: *const u8,
    len: usize,
    pattern: &[u8],
) -> Option<*mut u8> {
    let data = core::slice::from_raw_parts(start_address, len);
    data.windows(pattern.len())
        .position(|window| window == pattern)
        .map(|pos| start_address.add(pos) as *mut u8)
}

pub unsafe fn find_all_patterns(
    start_address: *const u8,
    len: usize,
    pattern: &[u8],
) -> std::vec::Vec<*mut u8> {
    let data = core::slice::from_raw_parts(start_address, len);
    data.windows(pattern.len())
        .enumerate()
        .filter(|(_, window)| window == &pattern)
        .map(|(pos, _)| start_address.add(pos) as *mut u8)
        .collect()
}

pub fn get_cstr_len(pointer: *const i8) -> usize {
    let mut tmp: u64 = pointer as u64;
    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }
    (tmp - pointer as u64) as _
}

pub unsafe fn find_syscall_instruction(function_ptr: *mut u8) -> Option<*mut u8> {
    let slice = core::slice::from_raw_parts(function_ptr, 32);
    slice
        .windows(2)
        .position(|w| w == [0x0F, 0x05])
        .map(|pos| function_ptr.add(pos))
}
