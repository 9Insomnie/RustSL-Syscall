use std::ffi::c_void;
use crate::ntapi::types::*;
use crate::syscall::common::hwbp::{set_hwbp, clear_hwbp, HWBPType, HWBPSize};
use crate::syscall::common::{env::get_loaded_module_by_hash, pe::get_export_by_hash};
use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
use crate::ntapi::EXCEPTION_SINGLE_STEP;
use crate::syscall::common::{get_ssn, find_syscall_instruction};

const NTDLL_HASH: u32 = crate::dbj2_hash!(b"ntdll.dll");
const RTL_ADD_VEH_HASH: u32 = crate::dbj2_hash!(b"RtlAddVectoredExceptionHandler");
const RTL_REMOVE_VEH_HASH: u32 = crate::dbj2_hash!(b"RtlRemoveVectoredExceptionHandler");

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

pub struct VehGuard {
    handle: *mut c_void,
    remove_fn: RtlRemoveVehFn,
}

impl Drop for VehGuard {
    fn drop(&mut self) {
        unsafe { (self.remove_fn)(self.handle); }
    }
}

pub unsafe fn register_veh() -> crate::utils::error::RslResult<VehGuard> {
    let ntdll = get_loaded_module_by_hash(NTDLL_HASH).ok_or("Failed to get ntdll")?;

    let rtl_add_veh_addr = get_export_by_hash(ntdll, RTL_ADD_VEH_HASH).ok_or("VEH API not found")?;
    let rtl_add_veh: RtlAddVehFn = std::mem::transmute(rtl_add_veh_addr);

    let rtl_remove_veh_addr = get_export_by_hash(ntdll, RTL_REMOVE_VEH_HASH).ok_or("VEH API not found")?;
    let rtl_remove_veh: RtlRemoveVehFn = std::mem::transmute(rtl_remove_veh_addr);

    let veh_handle = rtl_add_veh(1, exception_handler as *mut c_void);
    if veh_handle.is_null() {
        return Err(crate::utils::error::RslError::Other("Failed to register VEH".to_string()));
    }

    Ok(VehGuard { handle: veh_handle, remove_fn: rtl_remove_veh })
}

pub unsafe fn execute_with_hwbp(ntdll: *mut u8, func_hash: u32, callback: &mut dyn FnMut(*mut u8) -> i32) -> crate::utils::error::RslResult<()> {
    let func_addr = unsafe { get_export_by_hash(ntdll, func_hash) }.ok_or(format!("API {:#x} not found", func_hash))?;

    let hook_addr = (func_addr as usize) + 3;
    unsafe { set_hwbp(0, hook_addr, HWBPType::Execute, HWBPSize::Byte); }
    
    let status = callback(func_addr);
    
    unsafe { clear_hwbp(0); }
    
    if status < 0 {
        return Err(crate::utils::error::RslError::Other(format!("API {:#x} failed: {:#x}", func_hash, status)));
    }
    Ok(())
}

pub unsafe extern "system" fn exception_handler(
    exception_info: *mut EXCEPTION_POINTERS
) -> i32 {
    let exception_record = (*exception_info).ExceptionRecord;
    let context_record = (*exception_info).ContextRecord;
    
    if (*exception_record).ExceptionCode == EXCEPTION_SINGLE_STEP as i32 {
        if (*context_record).Rip == (*context_record).Dr0 {

            (*context_record).Dr0 = 0;
            (*context_record).Dr7 &= !1;

            let function_addr = ((*context_record).Rip - 3) as *mut u8;

            if let Some(ssn) = get_ssn(function_addr) {
                #[cfg(feature = "debug")]
                crate::utils::print_message(&format!("SSN found: {:#x}", ssn));
                (*context_record).Rax = ssn as u64;
            } else {
            }

            if let Some(syscall_addr) = find_syscall_instruction(function_addr) {
                (*context_record).Rip = syscall_addr as u64;
            } else {
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
        }
    } else {
        #[cfg(feature = "debug")]
        crate::utils::print_message("Not a SINGLE_STEP exception");
    }

    EXCEPTION_CONTINUE_SEARCH
}