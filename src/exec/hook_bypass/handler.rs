use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
use crate::api::EXCEPTION_SINGLE_STEP;
use super::ssn_helper;

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

pub unsafe extern "system" fn exception_handler(
    exception_info: *mut EXCEPTION_POINTERS
) -> i32 {
    let exception_record = (*exception_info).ExceptionRecord;
    let context_record = (*exception_info).ContextRecord;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Exception handler called. Code: {:#x}, RIP: {:#x}, Dr0: {:#x}", 
        (*exception_record).ExceptionCode, (*context_record).Rip, (*context_record).Dr0));
    
    if (*exception_record).ExceptionCode == EXCEPTION_SINGLE_STEP as i32 {
        if (*context_record).Rip == (*context_record).Dr0 {
            #[cfg(feature = "debug")]
            crate::utils::print_message("HWBP hit!");

            (*context_record).Dr0 = 0;
            (*context_record).Dr7 &= !1;

            let function_addr = ((*context_record).Rip - 3) as *mut u8;

            if let Some(ssn) = ssn_helper::get_ssn(function_addr) {
                #[cfg(feature = "debug")]
                crate::utils::print_message(&format!("SSN found: {:#x}", ssn));
                (*context_record).Rax = ssn as u64;
            } else {
                #[cfg(feature = "debug")]
                crate::utils::print_message("Failed to find SSN!");
            }

            if let Some(syscall_addr) = ssn_helper::get_syscall_instruction_address(function_addr) {
                #[cfg(feature = "debug")]
                crate::utils::print_message(&format!("Syscall instruction found at: {:#x}", syscall_addr));
                (*context_record).Rip = syscall_addr as u64;
            } else {
                #[cfg(feature = "debug")]
                crate::utils::print_message("Failed to find syscall instruction!");
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            #[cfg(feature = "debug")]
            crate::utils::print_message("RIP does not match Dr0");
        }
    } else {
        #[cfg(feature = "debug")]
        crate::utils::print_message("Not a SINGLE_STEP exception");
    }

    EXCEPTION_CONTINUE_SEARCH
}
