pub fn freshycalls_syswhispers(
    module_base: *mut u8,
    module_hash: u32,
) -> Option<*mut u8> {
    use crate::syscall::common::*;
    use crate::utils::dbj2_hash;
    use std::collections::BTreeMap;

    let mut nt_exports = BTreeMap::new();

    for (name, addr) in unsafe { get_exports_by_name(module_base) } {
        if name.starts_with("Zw") {
            nt_exports.insert(name.replace("Zw", "Nt"), addr);
        }
    }

    let mut nt_exports_vec: Vec<(String, usize)> = Vec::from_iter(nt_exports);
    // sort all Nt functions by address
    nt_exports_vec.sort_by_key(|k| k.1);

    // First Nt addresses has system call number of 0 and so on...

    let mut syscall_number: u16 = 0;

    for (name, addr) in nt_exports_vec {
        if module_hash == dbj2_hash(name.as_bytes()) {
            let addr_ptr = addr as *mut u8;

            #[cfg(feature = "debug")]
            crate::utils::print_message(&format!(
                "syscall: matched name={} addr={:#x}",
                name,
                addr
            ));

            return Some(addr_ptr);
        }
        syscall_number = syscall_number.wrapping_add(1);
    }

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!(
        "syscall: no match found for module_hash={:#x}",
        module_hash
    ));

    None
}