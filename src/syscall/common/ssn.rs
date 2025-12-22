pub fn find_syscall_number(function_ptr: *mut u8) -> u16 {
    let needle: [u8; 4] = [0x4c, 0x8b, 0xd1, 0xb8];
    let func_slice: &[u8] = unsafe { core::slice::from_raw_parts(function_ptr as *const u8, 6) };
    if let Some(index) = func_slice.windows(needle.len()).position(|x| *x == needle) {
        let offset = index + needle.len();
        return u16::from_le_bytes(func_slice[offset..offset + 2].try_into().unwrap());
    }
    0
}

pub unsafe fn is_syscall_stub(addr: *mut u8) -> bool {
    if addr.is_null() { return false; }
    let header = addr.read() == 0x4c && addr.add(1).read() == 0x8b 
        && addr.add(2).read() == 0xd1 && addr.add(3).read() == 0xb8;
    let footer = addr.add(6).read() == 0x00 && addr.add(7).read() == 0x00;
    header && footer
}

pub unsafe fn extract_ssn(addr: *mut u8) -> u16 {
    let low = addr.add(4).read();
    let high = addr.add(5).read();
    ((high as u16) << 8) | (low as u16)
}

pub unsafe fn scan_neighbor_ssn(target_addr: *mut u8, idx: usize, search_up: bool) -> Option<u16> {
    const DISTANCE: usize = 32;
    let neighbor_addr = if search_up {
        target_addr.wrapping_sub(idx * DISTANCE)
    } else {
        target_addr.wrapping_add(idx * DISTANCE)
    };

    if is_syscall_stub(neighbor_addr) {
        let neighbor_ssn = extract_ssn(neighbor_addr);
        return if search_up { Some(neighbor_ssn + idx as u16) } 
               else { Some(neighbor_ssn.saturating_sub(idx as u16)) };
    }
    None
}

pub unsafe fn get_ssn(function_ptr: *mut u8) -> Option<u16> {
    let ssn = find_syscall_number(function_ptr);
    if ssn != 0 {
        return Some(ssn);
    }

    #[cfg(feature = "debug")]
    crate::utils::print_message("SSN not found in prologue, trying neighbor scanning...");

    for i in 1..500 {
        if let Some(ssn) = scan_neighbor_ssn(function_ptr, i, false) {
            return Some(ssn);
        }
        if let Some(ssn) = scan_neighbor_ssn(function_ptr, i, true) {
            return Some(ssn);
        }
    }

    None
}
