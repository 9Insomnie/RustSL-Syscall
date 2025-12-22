use std::ptr;
use std::sync::atomic::Ordering;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use crate::syscall::common::*;
use super::state::*;
use super::handler::{hw_syscall_exception_handler, prepare_syscall};

pub unsafe fn init_hw_syscalls() -> bool {
    #[cfg(feature = "debug")]
    crate::utils::print_message("HWSyscalls: Initializing...");

    let ntdll_ptr = get_loaded_module_by_hash(crate::dbj2_hash!(b"ntdll.dll"))
        .expect("Unable to load ntdll");
    NTDLL_HANDLE.store(ntdll_ptr, Ordering::SeqCst);

    if let Some(gadget_addr) = find_suitable_ret_gadget() {
        RET_GADGET_ADDRESS.store(gadget_addr, Ordering::SeqCst);
    } else {
        #[cfg(feature = "debug")]
        crate::utils::print_error("HWSyscalls", &"Unable to find RET Gadget");
        return false;
    }

    EXCEPTION_HANDLER_HANDLE = AddVectoredExceptionHandler(1, Some(hw_syscall_exception_handler));
    if EXCEPTION_HANDLER_HANDLE.is_null() { return false; }

    set_main_breakpoint()
}

pub unsafe fn set_main_breakpoint() -> bool {
    set_hwbp(0, prepare_syscall as *const () as usize, HWBPType::Execute, HWBPSize::Byte)
}

pub unsafe fn deinit_hw_syscalls() -> bool {
    if !EXCEPTION_HANDLER_HANDLE.is_null() {
        RemoveVectoredExceptionHandler(EXCEPTION_HANDLER_HANDLE);
        EXCEPTION_HANDLER_HANDLE = ptr::null_mut();
    }

    let thread_handle = GetCurrentThread();
    let mut ctx: CONTEXT = std::mem::zeroed();
    
    // CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
    ctx.ContextFlags = 0x00100000 | 0x00000010;

    if GetThreadContext(thread_handle, &mut ctx) != 0 {
        ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0;
        ctx.Dr6 = 0; ctx.Dr7 = 0; 
        SetThreadContext(thread_handle, &ctx);
    }

    true
}
