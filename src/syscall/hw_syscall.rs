#![allow(non_snake_case, unused)]
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, AtomicU32, Ordering};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use crate::syscall::common::*;

// --- 全局状态机变量 (use atomics instead of mutable statics) ---
static mut EXCEPTION_HANDLER_HANDLE: *mut core::ffi::c_void = ptr::null_mut();
static NTDLL_HANDLE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static RET_GADGET_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static NT_FUNCTION_ADDRESS: AtomicUsize = AtomicUsize::new(0);
// Temporary storage for the requested function hash — VEH will read this instead of ctx.Rcx
static TARGET_HASH: AtomicU32 = AtomicU32::new(0);

/// 原项目 PrepareSyscall 桩函数
#[no_mangle]
#[inline(never)]
pub extern "C" fn prepare_syscall(function_hash: u32) -> usize {
    // RCX = function_hash
    unsafe { NT_FUNCTION_ADDRESS.load(std::sync::atomic::Ordering::SeqCst) }
}

pub unsafe fn init_hw_syscalls() -> bool {
    #[cfg(feature = "debug")]
    crate::utils::print_message("HWSyscalls init...");

    let ntdll_ptr = get_loaded_module_by_hash(crate::dbj2_hash!("ntdll.dll".as_bytes()))
        .expect("Unable to load ntdll");
    NTDLL_HANDLE.store(ntdll_ptr, Ordering::SeqCst);

    if let Some(gadget_addr) = find_suitable_ret_gadget() {
        RET_GADGET_ADDRESS.store(gadget_addr, Ordering::SeqCst);
    } else {
        #[cfg(feature = "debug")]
        crate::utils::print_message("Error: Unable to find RET Gadget");
        return false;
    }

    EXCEPTION_HANDLER_HANDLE = AddVectoredExceptionHandler(1, Some(hw_syscall_exception_handler));
    if EXCEPTION_HANDLER_HANDLE.is_null() { return false; }

    set_main_breakpoint()
}

pub unsafe fn set_main_breakpoint() -> bool {
    set_hwbp(0, prepare_syscall as *const () as usize, HWBPType::Execute, HWBPSize::Byte)
}

pub unsafe extern "system" fn hw_syscall_exception_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let ctx = &mut *(*info).ContextRecord;
    let rec = &*(*info).ExceptionRecord;

    if rec.ExceptionCode != 0x80000004u32 as i32 { return 0; }

    if ctx.Rip == prepare_syscall as *const () as u64 {
        #[cfg(feature = "debug")]
        crate::utils::print_message("PrepareSyscall 断点触发");
        // read requested hash from atomic to avoid relying on RCX consistency
        let target_hash = TARGET_HASH.load(Ordering::SeqCst);

        // fetch ntdll base from atomic (may be set in init)
        let ntdll_base = NTDLL_HANDLE.load(Ordering::SeqCst);

        if let Some(addr) = get_export_by_hash(ntdll_base, target_hash) {
            NT_FUNCTION_ADDRESS.store(addr as usize, Ordering::SeqCst);
            set_hwbp(0, addr as usize, HWBPType::Execute, HWBPSize::Byte);
        }

        ctx.EFlags |= 0x10000;
        return -1;
    }

    if ctx.Rip == NT_FUNCTION_ADDRESS.load(std::sync::atomic::Ordering::SeqCst) as u64 {

        ctx.Rsp -= 0x70;
        *(ctx.Rsp as *mut usize) = RET_GADGET_ADDRESS.load(Ordering::SeqCst);

        // 2. 参数迁移
        for i in 0..16 {
            let src = (ctx.Rsp + 0x70 + (i * 8) + 0x28) as *const u64;
            let dst = (ctx.Rsp + (i * 8) + 0x28) as *mut u64;
            if !src.is_null() && !dst.is_null() { *dst = *src; }
        }

        let p_address = NT_FUNCTION_ADDRESS.load(Ordering::SeqCst) as *mut u8;
        let mut ssn: u16 = 0;

        if is_syscall_stub(p_address) {
            ssn = extract_ssn(p_address);
        } else {
            for idx in 1..500 {
                if let Some(s) = scan_neighbor_ssn(p_address, idx, false) { ssn = s; break; }
                if let Some(s) = scan_neighbor_ssn(p_address, idx, true) { ssn = s; break; }
            }
        }

        if ssn != 0 {
            ctx.Rax = ssn as u64;
            ctx.R10 = ctx.Rcx;
            
            if let Some(syscall_ret_addr) = find_syscall_ret_in_stub(p_address) {
                ctx.Rip = syscall_ret_addr as u64;
            }
        }

        set_hwbp(0, prepare_syscall as *const () as usize, HWBPType::Execute, HWBPSize::Byte);

        ctx.EFlags |= 0x10000;
        return -1;
    }

    0
}

pub unsafe fn get_hw_syscall(
    _module_base: *mut u8,
    module_hash: u32,
) -> Option<*mut u8> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("get_hw_syscall: module_hash={:#x}", module_hash));
    // store the requested hash in an atomic so VEH reads a stable value
    TARGET_HASH.store(module_hash, Ordering::SeqCst);
    let function_address = prepare_syscall(module_hash);
    if function_address == 0 { return None; }
    // clear the target hash to avoid stale values
    TARGET_HASH.store(0, Ordering::SeqCst);

    Some(function_address as *mut u8)
}

unsafe fn find_syscall_ret_in_stub(p_addr: *mut u8) -> Option<usize> {
    let slice = core::slice::from_raw_parts(p_addr, 32);
    slice.windows(2).position(|w| w == [0x0F, 0x05]).map(|pos| p_addr.add(pos) as usize)
}

pub unsafe fn deinit_hw_syscalls() -> bool {
    if !EXCEPTION_HANDLER_HANDLE.is_null() {
        RemoveVectoredExceptionHandler(EXCEPTION_HANDLER_HANDLE);
        EXCEPTION_HANDLER_HANDLE = ptr::null_mut();
    }

    let thread_handle = GetCurrentThread();
    let mut ctx: CONTEXT = std::mem::zeroed();
    
    const CONTEXT_AMD64: u32 = 0x00100000;
    const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if GetThreadContext(thread_handle, &mut ctx) != 0 {
        ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0;
        ctx.Dr6 = 0; ctx.Dr7 = 0; 
        SetThreadContext(thread_handle, &ctx);
    }

    true
}