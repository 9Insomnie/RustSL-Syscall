use crate::syscall::common::{get_export_by_hash, get_ssn, find_syscall_instruction, find_syscall_gadget, SyscallData};

pub unsafe fn hells_halos_tartarus_gate(
    module_base: *mut u8,
    module_hash: u32,
) -> Option<SyscallData> {
    let p_address = get_export_by_hash(module_base, module_hash)?;
    let addr = p_address as usize;

    if let Some(ssn) = get_ssn(p_address) {
        let syscall_inst = find_syscall_instruction(p_address)
            .map(|p| p as usize)
            .unwrap_or_else(|| {
                find_syscall_gadget(module_base).map(|p| p as usize).unwrap_or(0)
            });

        return Some(SyscallData {
            entry: addr,
            ssn,
            syscall_inst,
        });
    }

    None
}