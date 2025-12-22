use crate::syscall::common::{get_export_by_hash, is_syscall_stub, scan_neighbor_ssn};

pub unsafe fn hells_halos_tartarus_gate(
    module_base: *mut u8,
    module_hash: u32,
) -> Option<*mut u8> {
    let p_address = get_export_by_hash(module_base, module_hash)?;

    if is_syscall_stub(p_address) {
        return Some(p_address);
    }

    if p_address.read() == 0xe9 || p_address.add(3).read() == 0xe9 {
        for idx in 1..500 {
            if let Some(_) = scan_neighbor_ssn(p_address, idx, false) {
                return Some(p_address);
            }
            if let Some(_) = scan_neighbor_ssn(p_address, idx, true) {
                return Some(p_address);
            }
        }
    }

    None
}
