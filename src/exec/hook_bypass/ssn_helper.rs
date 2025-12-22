pub unsafe fn get_syscall_instruction_address(function_ptr: *mut u8) -> Option<usize> {
    let slice = core::slice::from_raw_parts(function_ptr, 32);
    if let Some(pos) = slice.windows(2).position(|window| window == [0x0f, 0x05]) {
        return Some(function_ptr as usize + pos);
    }
    None
}

pub unsafe fn get_ssn(function_ptr: *mut u8) -> Option<u16> {
    let ssn = crate::syscall::common::ssn::find_syscall_number(function_ptr);
    if ssn != 0 {
        return Some(ssn);
    }

    #[cfg(feature = "debug")]
    crate::utils::print_message("SSN not found in prologue, trying neighbor scanning...");

    for i in 1..500 {
        if let Some(ssn) = crate::syscall::common::ssn::scan_neighbor_ssn(function_ptr, i, false) {
            return Some(ssn);
        }
        if let Some(ssn) = crate::syscall::common::ssn::scan_neighbor_ssn(function_ptr, i, true) {
            return Some(ssn);
        }
    }

    None
}
