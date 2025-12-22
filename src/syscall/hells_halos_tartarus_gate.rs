use crate::syscall::common::{get_export_by_hash, get_ssn};

pub unsafe fn hells_halos_tartarus_gate(
    module_base: *mut u8,
    module_hash: u32,
) -> Option<*mut u8> {
    let p_address = get_export_by_hash(module_base, module_hash)?;

    if get_ssn(p_address).is_some() {
        return Some(p_address);
    }

    None
}
