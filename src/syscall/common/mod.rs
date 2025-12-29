#![allow(dead_code, unused_imports)]

pub mod pe;
pub mod env;
pub mod scanner;
pub mod ssn;
pub mod hwbp;
pub mod spoof;

pub use pe::*;
pub use env::*;
pub use scanner::*;
pub use ssn::*;
pub use hwbp::*;
pub use spoof::*;

pub mod gadget;
pub use gadget::*;

mod r#type;
pub use r#type::*;

pub fn get_process_id_by_name(name_hash: u32) -> Result<u32, String> {
    use crate::api;
    use obfstr::obfstr;

    // Allocate a large buffer (e.g., 1MB)
    let buf_size = 1024 * 1024;
    let buf_ptr = api::alloc_virtual_memory(buf_size, api::PAGE_READWRITE).map_err(|_| "Alloc failed")? as *mut u8;
    
    let mut return_len = 0;
    let status = api::query_system_information(
        5u32, // SystemProcessInformation
        buf_ptr,
        buf_size as u32,
        &mut return_len
    )?;

    if status < 0 {
        // Free memory
        let _ = api::free_virtual_memory(-1, buf_ptr, buf_size);
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
                    let _ = api::free_virtual_memory(-1, buf_ptr, buf_size);
                    return Ok(pid);
                }
            }
        }

        if next_offset == 0 {
            break;
        }
        offset += next_offset as usize;
    }

    let _ = api::free_virtual_memory(-1, buf_ptr, buf_size);
    Err("Process not found".to_string())
}

pub fn is_wow64() -> bool {
    std::mem::size_of::<usize>() == 8
}