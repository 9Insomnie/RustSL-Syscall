pub unsafe fn is_syscall_stub(addr: *mut u8) -> bool {
    if addr.is_null() {
        return false;
    }
    // Check for: mov r10, rcx; mov eax, <ssn>
    // 4C 8B D1 B8
    addr.read() == 0x4C
        && addr.add(1).read() == 0x8B
        && addr.add(2).read() == 0xD1
        && addr.add(3).read() == 0xB8
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
        return if search_up {
            Some(neighbor_ssn + idx as u16)
        } else {
            Some(neighbor_ssn.saturating_sub(idx as u16))
        };
    }
    None
}

pub unsafe fn get_ssn(function_ptr: *mut u8) -> Option<u16> {
    if is_syscall_stub(function_ptr) {
        return Some(extract_ssn(function_ptr));
    }

    #[cfg(feature = "debug")]
    crate::utils::print_error(
        "Error",
        &"SSN not found in prologue, trying neighbor scanning...",
    );

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
