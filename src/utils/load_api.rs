#![allow(non_snake_case, non_camel_case_types)]

use crate::utils::dbj2_hash;
use std::ffi::c_void;

/// Lightweight wrappers that reuse `utils::get` implementations to avoid duplication.
pub unsafe fn load_library(dll_name: &[u8]) -> crate::utils::error::RslResult<isize> {
    use obfstr::obfstr;
    use rsl_macros::obfuscation_noise_macro;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let name_str = String::from_utf8_lossy(dll_name);
    let name_trimmed = name_str.trim_matches(char::from(0));
    let module_hash = dbj2_hash(name_trimmed.as_bytes());

    // Delegate to utils::get::get_loaded_module_by_hash
    if let Some(base) = crate::syscall::common::get_loaded_module_by_hash(module_hash) {
        obfuscation_noise_macro!();
        Ok(base as isize)
    } else {
        let dll = LoadLibraryA(dll_name.as_ptr() as *const u8);
        if dll == 0 {
            Err(crate::utils::error::RslError::Other(
                obfstr!("LoadLibraryA failed").to_string(),
            ))
        } else {
            obfuscation_noise_macro!();
            #[cfg(feature = "debug")]
            crate::utils::print_message(&format!(
                "{} {}",
                obfstr!("Module loaded by LoadLibraryA:"),
                name_trimmed
            ));
            Ok(dll)
        }
    }
}

pub unsafe fn get_proc_address(
    dll: isize,
    name: &[u8],
) -> crate::utils::error::RslResult<*const ()> {
    use obfstr::obfstr;
    use rsl_macros::obfuscation_noise_macro;
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

    let name_str = String::from_utf8_lossy(name);
    let name_trimmed = name_str.trim_matches(char::from(0));
    let proc_hash = dbj2_hash(name_trimmed.as_bytes());

    // Delegate to utils::get::get_export_by_hash
    if let Some(addr) = crate::syscall::common::get_export_by_hash(dll as *mut u8, proc_hash) {
        obfuscation_noise_macro!();
        Ok(addr as *const ())
    } else {
        let addr = GetProcAddress(dll, name.as_ptr() as *const u8);
        if let Some(f) = addr {
            obfuscation_noise_macro!();
            Ok(f as *const ())
        } else {
            Err(crate::utils::error::RslError::Other(
                obfstr!("GetProcAddress failed").to_string(),
            ))
        }
    }
}
