use super::*;

pub unsafe fn find_gadget_in_module(module_base: *mut u8, pattern: &[u8]) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    find_pattern(module_base, image_size, pattern)
}

pub unsafe fn find_random_gadget_in_module(module_base: *mut u8, pattern: &[u8]) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let gadgets = find_all_patterns(module_base, image_size, pattern);
    
    if gadgets.is_empty() {
        return None;
    }

    // Simple PRNG using rdtsc
    let tsc = core::arch::x86_64::_rdtsc();
    let index = (tsc as usize) % gadgets.len();
    Some(gadgets[index])
}

pub unsafe fn find_ret_gadget(module_name_hash: u32) -> Option<usize> {
    let module_base = get_loaded_module_by_hash(module_name_hash)?;
    let pattern = [0x48, 0x83, 0xC4, 0x68, 0xC3];
    find_gadget_in_module(module_base, &pattern).map(|p| p as usize)
}

pub unsafe fn find_suitable_ret_gadget() -> Option<usize> {
    let k32_hash = crate::dbj2_hash!(b"kernel32.dll");
    let kbase_hash = crate::dbj2_hash!(b"kernelbase.dll");

    if let Some(addr) = find_ret_gadget(k32_hash) { return Some(addr); }
    if let Some(addr) = find_ret_gadget(kbase_hash) { return Some(addr); }
    None
}

pub unsafe fn find_syscall_gadget(module_base: *mut u8) -> Option<*mut u8> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Searching for syscall; ret gadget in ntdll...");

    let pattern = [0x0F, 0x05, 0xC3];
    let gadget = find_gadget_in_module(module_base, &pattern);

    #[cfg(feature = "debug")]
    if let Some(addr) = gadget {
        crate::utils::print_message(&format!("Found syscall; ret gadget at {:p}", addr));
    } else {
        crate::utils::print_error("Scanner", &"Failed to find syscall; ret gadget");
    }

    gadget
}
