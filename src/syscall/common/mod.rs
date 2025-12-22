#![allow(dead_code, unused_imports)]

pub mod pe;
pub mod env;
pub mod scanner;
pub mod ssn;
pub mod hwbp;

pub use pe::*;
pub use env::*;
pub use scanner::*;
pub use ssn::*;
pub use hwbp::*;

pub fn is_wow64() -> bool {
    std::mem::size_of::<usize>() == 8
}

pub unsafe fn find_ret_gadget(module_name_hash: u32) -> Option<usize> {
    let module_base = get_loaded_module_by_hash(module_name_hash)?;
    let nt_headers = get_nt_headers(module_base)?;
    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let pattern = [0x48, 0x83, 0xC4, 0x68, 0xC3];

    if let Some(gadget_ptr) = find_pattern(module_base, image_size, &pattern) {
        return Some(gadget_ptr as usize);
    }
    None
}

pub unsafe fn find_suitable_ret_gadget() -> Option<usize> {
    let k32_hash = crate::dbj2_hash!(b"kernel32.dll");
    let kbase_hash = crate::dbj2_hash!(b"kernelbase.dll");

    if let Some(addr) = find_ret_gadget(k32_hash) { return Some(addr); }
    if let Some(addr) = find_ret_gadget(kbase_hash) { return Some(addr); }
    None
}
pub unsafe fn find_syscall_gadget(module_base: *mut u8) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let pattern = [0x0F, 0x05, 0xC3];

    #[cfg(feature = "debug")]
    crate::utils::print_message("Searching for syscall; ret gadget in ntdll...");

    let gadget = find_pattern(module_base, image_size, &pattern);

    #[cfg(feature = "debug")]
    if let Some(addr) = gadget {
        crate::utils::print_message(&format!("Found syscall; ret gadget at {:p}", addr));
    } else {
        crate::utils::print_error("Scanner", &"Failed to find syscall; ret gadget");
    }

    gadget
}
