#![allow(non_snake_case, dead_code, unused_variables, unused_imports, non_camel_case_types)]
use crate::api;
use obfstr::obfstr;

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    exit_status: i32,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

pub unsafe fn get_remote_peb_addr(process_handle: isize) -> Result<usize, String> {
    use core::ffi::c_void;

    let mut pbi = PROCESS_BASIC_INFORMATION {
        exit_status: 0,
        peb_base_address: 0,
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let mut return_len: u32 = 0;

    let status = api::query_information_process(
        process_handle,
        0u32, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut return_len
    )?;

    if status < 0 {
        return Err(format!("NtQueryInformationProcess failed: {:#x}", status));
    }

    Ok(pbi.peb_base_address)
}

pub unsafe fn get_remote_module_base(process_handle: isize, dll_name_hash: u32) -> Result<usize, String> {
    let peb_addr = get_remote_peb_addr(process_handle)?;
    
    // PEB + 0x18 = Ldr (x64)
    let mut ldr_ptr_buf = [0u8; 8];
    api::read_virtual_memory(process_handle, peb_addr + 0x18, &mut ldr_ptr_buf)?;
    let ldr_addr = usize::from_le_bytes(ldr_ptr_buf);

    // Ldr + 0x20 = InMemoryOrderModuleList (LIST_ENTRY)
    // We start at the first entry
    let mut current_entry_buf = [0u8; 8];
    api::read_virtual_memory(process_handle, ldr_addr + 0x20, &mut current_entry_buf)?;
    let mut current_entry = usize::from_le_bytes(current_entry_buf);
    let head = ldr_addr + 0x20;

    // Loop limit to prevent infinite loop
    for _ in 0..100 {
        if current_entry == head || current_entry == 0 {
            break;
        }

        let name_struct_addr = current_entry + 0x48;
        let mut name_struct_buf = [0u8; 16]; // 2+2+4(padding)+8
        api::read_virtual_memory(process_handle, name_struct_addr, &mut name_struct_buf)?;
        
        let len = u16::from_le_bytes([name_struct_buf[0], name_struct_buf[1]]) as usize;
        let buffer_addr = usize::from_le_bytes([name_struct_buf[8], name_struct_buf[9], name_struct_buf[10], name_struct_buf[11], name_struct_buf[12], name_struct_buf[13], name_struct_buf[14], name_struct_buf[15]]);

        if len > 0 && buffer_addr != 0 {
            let mut name_buf = vec![0u8; len];
            if api::read_virtual_memory(process_handle, buffer_addr, &mut name_buf).is_ok() {
                // Convert UTF-16 to UTF-8 for hashing
                let name_u16: Vec<u16> = name_buf.chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                
                if let Ok(name_str) = String::from_utf16(&name_u16) {
                    let name_lower = name_str.to_lowercase();
                    if crate::utils::dbj2_hash(name_lower.as_bytes()) == dll_name_hash {
                        // Found it! Read DllBase
                        let mut dll_base_buf = [0u8; 8];
                        api::read_virtual_memory(process_handle, current_entry + 0x20, &mut dll_base_buf)?;
                        return Ok(usize::from_le_bytes(dll_base_buf));
                    }
                }
            }
        }

        // Move to next entry (Flink is at current_entry)
        api::read_virtual_memory(process_handle, current_entry, &mut current_entry_buf)?;
        current_entry = usize::from_le_bytes(current_entry_buf);
    }

    Err(obfstr!("Remote module not found").to_string())
}

pub unsafe fn get_remote_export_address(process_handle: isize, module_base: usize, export_name_hash: u32) -> Result<usize, String> {
    use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
    use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT};

    // Read DOS Header
    let mut dos_header_buf = [0u8; std::mem::size_of::<IMAGE_DOS_HEADER>()];
    api::read_virtual_memory(process_handle, module_base, &mut dos_header_buf)?;
    let dos_header: IMAGE_DOS_HEADER = std::ptr::read(dos_header_buf.as_ptr() as *const _);

    // Read NT Headers
    let nt_headers_addr = module_base + dos_header.e_lfanew as usize;
    let mut nt_headers_buf = [0u8; std::mem::size_of::<IMAGE_NT_HEADERS64>()];
    api::read_virtual_memory(process_handle, nt_headers_addr, &mut nt_headers_buf)?;
    let nt_headers: IMAGE_NT_HEADERS64 = std::ptr::read(nt_headers_buf.as_ptr() as *const _);

    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize;
    if export_dir_rva == 0 {
        return Err(obfstr!("No export directory").to_string());
    }

    let export_dir_addr = module_base + export_dir_rva;
    let mut export_dir_buf = [0u8; std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>()];
    api::read_virtual_memory(process_handle, export_dir_addr, &mut export_dir_buf)?;
    let export_dir: IMAGE_EXPORT_DIRECTORY = std::ptr::read(export_dir_buf.as_ptr() as *const _);

    let names_addr = module_base + export_dir.AddressOfNames as usize;
    let ordinals_addr = module_base + export_dir.AddressOfNameOrdinals as usize;
    let functions_addr = module_base + export_dir.AddressOfFunctions as usize;

    // Iterate names
    // Optimization: Read chunks of names? For now, read one by one.
    for i in 0..export_dir.NumberOfNames {
        let mut name_rva_buf = [0u8; 4];
        api::read_virtual_memory(process_handle, names_addr + (i as usize * 4), &mut name_rva_buf)?;
        let name_rva = u32::from_le_bytes(name_rva_buf) as usize;
        let name_addr = module_base + name_rva;

        // Read name string (assume max 64 chars)
        let mut name_buf = [0u8; 64];
        api::read_virtual_memory(process_handle, name_addr, &mut name_buf)?;
        
        // Find null terminator
        let len = name_buf.iter().position(|&c| c == 0).unwrap_or(64);
        let name_slice = &name_buf[0..len];

        if crate::utils::dbj2_hash(name_slice) == export_name_hash {
            // Found match
            let mut ordinal_buf = [0u8; 2];
            api::read_virtual_memory(process_handle, ordinals_addr + (i as usize * 2), &mut ordinal_buf)?;
            let ordinal = u16::from_le_bytes(ordinal_buf) as usize;

            let mut func_rva_buf = [0u8; 4];
            api::read_virtual_memory(process_handle, functions_addr + (ordinal * 4), &mut func_rva_buf)?;
            let func_rva = u32::from_le_bytes(func_rva_buf) as usize;

            return Ok(module_base + func_rva);
        }
    }

    Err(obfstr!("Export not found").to_string())
}

pub fn find_process_id_by_name(name_hash: u32) -> Result<u32, String> {
    // Allocate a large buffer (e.g., 1MB)
    // We can use our own alloc_virtual_memory for this buffer in current process
    let buf_size = 1024 * 1024;
    let buf_ptr = crate::api::alloc_virtual_memory(buf_size, crate::api::PAGE_READWRITE).map_err(|_| "Alloc failed")? as *mut u8;
    
    let mut return_len = 0;
    let status = api::query_system_information(
        5u32, // SystemProcessInformation
        buf_ptr,
        buf_size as u32,
        &mut return_len
    )?;

    if status < 0 {
        // Free memory
        let _ = crate::api::free_virtual_memory(-1, buf_ptr, buf_size);
        return Err("NtQuerySystemInformation failed".to_string());
    }

    let mut offset = 0;
    loop {
        let curr_ptr = unsafe { buf_ptr.add(offset) };
        
        // Read NextEntryOffset
        let next_offset = unsafe { *(curr_ptr as *const u32) };
        
        // Read ImageName (UNICODE_STRING at 0x38)
        let name_len = unsafe { *(curr_ptr.add(0x38) as *const u16) };
        let name_buf_ptr = unsafe { *(curr_ptr.add(0x38 + 8) as *const usize) } as *const u16;
        
        if name_len > 0 && !name_buf_ptr.is_null() {
            let name_slice = unsafe { std::slice::from_raw_parts(name_buf_ptr, (name_len / 2) as usize) };
            if let Ok(name_str) = String::from_utf16(name_slice) {
                if crate::utils::dbj2_hash(name_str.to_lowercase().as_bytes()) == name_hash {
                    // Found it
                    // UniqueProcessId is at offset 0x50 on x64
                    let pid = unsafe { *(curr_ptr.add(0x50) as *const usize) } as u32;
                    let _ = crate::api::free_virtual_memory(-1, buf_ptr, buf_size);
                    return Ok(pid);
                }
            }
        }

        if next_offset == 0 {
            break;
        }
        offset += next_offset as usize;
    }

    let _ = crate::api::free_virtual_memory(-1, buf_ptr, buf_size);
    Err("Process not found".to_string())
}

pub unsafe fn create_process(target_program: &str, creation_flags: u32) -> Result<windows_sys::Win32::System::Threading::PROCESS_INFORMATION, String> {
    use std::ffi::CString;
    use windows_sys::Win32::System::Threading::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA};
    use windows_sys::Win32::Foundation::{GetLastError, FALSE};

    let mut startup_info: STARTUPINFOA = std::mem::zeroed();
    let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let app_name = CString::new(target_program).map_err(|e| e.to_string())?;
    let success = CreateProcessA(
        std::ptr::null(),
        app_name.as_ptr() as *mut u8,
        std::ptr::null(),
        std::ptr::null(),
        0,
        creation_flags,
        std::ptr::null(),
        std::ptr::null(),
        &startup_info,
        &mut process_info,
    );

    if success == FALSE {
        return Err(format!("CreateProcessA failed: {}", GetLastError()));
    }

    Ok(process_info)
}
