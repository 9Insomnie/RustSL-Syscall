use std::sync::atomic::Ordering;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use crate::syscall::common::*;
use super::state::*;
use super::prepare_syscall;

pub unsafe extern "system" fn hw_syscall_exception_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let ctx = &mut *(*info).ContextRecord;
    let rec = &*(*info).ExceptionRecord;

    if rec.ExceptionCode != 0x80000004u32 as i32 { return 0; }

    if ctx.Rip == prepare_syscall as *const () as u64 {
        #[cfg(feature = "debug")]
        crate::utils::print_message("HWSyscalls: PrepareSyscall breakpoint triggered");
        
        // read requested hash from atomic to avoid relying on RCX consistency
        let target_hash = TARGET_HASH.load(Ordering::SeqCst);

        // fetch ntdll base from atomic
        let ntdll_base = NTDLL_HANDLE.load(Ordering::SeqCst);

        if let Some(addr) = get_export_by_hash(ntdll_base, target_hash) {
            NT_FUNCTION_ADDRESS.store(addr as usize, Ordering::SeqCst);
            set_hwbp(0, addr as usize, HWBPType::Execute, HWBPSize::Byte);
        }

        ctx.EFlags |= 0x10000;
        return -1;
    }

    if ctx.Rip == NT_FUNCTION_ADDRESS.load(Ordering::SeqCst) as u64 {
        // 1. Stack adjustment and gadget setup
        ctx.Rsp -= 0x70;
        *(ctx.Rsp as *mut usize) = RET_GADGET_ADDRESS.load(Ordering::SeqCst);

        // 2. Parameter migration (shadow space and args)
        for i in 0..16 {
            let src = (ctx.Rsp + 0x70 + (i * 8) + 0x28) as *const u64;
            let dst = (ctx.Rsp + (i * 8) + 0x28) as *mut u64;
            if !src.is_null() && !dst.is_null() { *dst = *src; }
        }

        let p_address = NT_FUNCTION_ADDRESS.load(Ordering::SeqCst) as *mut u8;
        let ssn = get_ssn(p_address).unwrap_or(0);

        if ssn != 0 {
            ctx.Rax = ssn as u64;
            ctx.R10 = ctx.Rcx;
            
            if let Some(syscall_ret_addr) = find_syscall_instruction(p_address) {
                ctx.Rip = syscall_ret_addr as u64;
            }
        }

        // Reset breakpoint to prepare_syscall for next call
        set_hwbp(0, prepare_syscall as *const () as usize, HWBPType::Execute, HWBPSize::Byte);

        ctx.EFlags |= 0x10000;
        return -1;
    }

    0
}
