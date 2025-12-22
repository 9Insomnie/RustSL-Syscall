pub mod stub;

use crate::syscall::common::*;
use stub::create_indirect_stub;

/// KFD (Konflict) style indirect syscall implementation.
/// It finds the SSN and a syscall; ret gadget in ntdll, 
/// then creates a small executable stub to perform the indirect call.
pub unsafe fn get_kfd_syscall(
    module_base: *mut u8,
    function_hash: u32,
) -> Option<*mut u8> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("KFD: Resolving syscall for hash: {:#x}", function_hash));

    // 1. Find the function address in ntdll
    let p_address = get_export_by_hash(module_base, function_hash)?;

    // 2. Extract SSN using common tools
    let ssn = get_ssn(p_address)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("KFD: Resolved SSN: {:#x}", ssn));

    // 3. Find a syscall; ret gadget in ntdll
    let gadget = find_syscall_gadget(module_base)?;

    // 4. Create an indirect stub that jumps to the gadget
    create_indirect_stub(ssn, gadget)
}
