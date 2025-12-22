use std::{collections::BTreeMap, ffi::CStr};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER},
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE},
};

#[cfg(target_arch = "x86")]
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE { return None; }
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ { return None; }
    Some(nt_headers)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE { return None; }
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ { return None; }
    Some(nt_headers)
}

pub unsafe fn get_export_directory_info(module_base: *mut u8) -> Option<(*mut IMAGE_EXPORT_DIRECTORY, &'static [u32], &'static [u32], &'static [u16])> {
    let nt_headers = get_nt_headers(module_base)?;
    let export_dir_va = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    if export_dir_va == 0 { return None; }
    
    let export_directory = (module_base as usize + export_dir_va as usize) as *mut IMAGE_EXPORT_DIRECTORY;
    let names = core::slice::from_raw_parts((module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = core::slice::from_raw_parts((module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32, (*export_directory).NumberOfFunctions as _);
    let ordinals = core::slice::from_raw_parts((module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);
    
    Some((export_directory, names, functions, ordinals))
}

pub unsafe fn get_exports_by_name(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let Some((export_directory, names, functions, ordinals)) = get_export_directory_info(module_base) else {
        return exports;
    };

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
            let ordinal = ordinals[i as usize] as usize;
            exports.insert(name.to_string(), module_base as usize + functions[ordinal] as usize);
        }
    }
    exports
}

pub unsafe fn get_export_by_hash(module_base: *mut u8, export_name_hash: u32) -> Option<*mut u8> {
    let (export_directory, names, functions, ordinals) = get_export_directory_info(module_base)?;

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = super::scanner::get_cstr_len(name_addr as _);
        let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

        if export_name_hash == crate::utils::dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            let addr = (module_base as usize + functions[ordinal] as usize) as *mut u8;
            #[cfg(feature = "debug")]
            crate::utils::print_message(&format!("get_export_by_hash: export matched: {} -> {:p}", String::from_utf8_lossy(name_slice), addr));
            return Some(addr);
        }
    }
    None
}

pub unsafe fn get_section_base_address(module_base: *mut u8, section_name: &str) -> Option<usize> {
    let nt_headers = get_nt_headers(module_base)?;
    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    let optional_header_offset = &(*nt_headers).OptionalHeader as *const _ as usize - nt_headers as usize;
    let first_section_offset = optional_header_offset + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize;
    let mut section_header = (nt_headers as usize + first_section_offset) as *mut IMAGE_SECTION_HEADER;

    for _ in 0..number_of_sections {
        let name_bytes = &(*section_header).Name;
        let name_len = name_bytes.iter().position(|&c| c == 0).unwrap_or(8);
        let name_str = std::str::from_utf8(&name_bytes[..name_len]).ok()?;
        
        if name_str == section_name {
            return Some(module_base as usize + (*section_header).VirtualAddress as usize);
        }
        
        section_header = section_header.add(1);
    }
    
    None
}