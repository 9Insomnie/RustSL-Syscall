use crate::ntapi::types::{
    LdrGetDllHandleByAddressFn, LocalAllocFn, NtQueryInformationThreadFn, TlsAllocFn,
    TlsGetValueFn, TlsSetValueFn, PVOID,
};
use crate::ntapi::TLS_OUT_OF_INDEXES;
use crate::{raw_syscall, syscall};
use core::ffi::c_void;
use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB, ntpsapi::PEB_LDR_DATA};
use std::arch::asm;

static mut TLS_INDEX: u32 = 0;

#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

pub unsafe fn get_peb() -> *mut PEB {
    (*get_teb()).ProcessEnvironmentBlock
}

pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();

    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;
    let mut module_list =
        (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length_chars = ((*module_list).BaseDllName.Length as usize) / 2;
        let dll_name_u16 = core::slice::from_raw_parts(dll_buffer_ptr, dll_length_chars);
        let dll_name_string = String::from_utf16_lossy(dll_name_u16);
        let dll_name_trimmed = dll_name_string.trim_matches(char::from(0));

        if module_hash == crate::utils::dbj2_hash(dll_name_trimmed.as_bytes()) {
            return Some((*module_list).DllBase as _);
        }
        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }
    None
}

// If it fails to do so, it will return the BaseThreadInitThunk's frame address instead.
pub fn get_desirable_return_address(current_rsp: usize, keep_start_function_frame: bool) -> usize {
    unsafe {
        let k32 = get_loaded_module_by_hash(crate::dbj2_hash!(b"kernel32.dll"))
            .unwrap_or(std::ptr::null_mut());
        let mut addr: usize = 0;
        let mut start_address = 1;
        let mut end_address = 0;
        let base_thread_init_thunk_start = crate::syscall::common::pe::get_export_by_hash(
            k32,
            crate::dbj2_hash!(b"BaseThreadInitThunk"),
        )
        .unwrap_or(std::ptr::null_mut());
        let base_thread_init_thunk_addresses = crate::syscall::common::pe::get_function_size(
            k32 as usize,
            base_thread_init_thunk_start as usize,
        );

        let base_thread_init_thunk_end = base_thread_init_thunk_addresses.1;

        let tls_get_value_ptr =
            crate::syscall::common::pe::get_export_by_hash(k32, crate::dbj2_hash!(b"TlsGetValue"))
                .unwrap();
        let tls_get_value: TlsGetValueFn = std::mem::transmute(tls_get_value_ptr);

        let thread_information = 0usize;
        let thread_information: PVOID = std::mem::transmute(&thread_information);
        let thread_info_len = 8u32;
        let ret_len = 0u32;
        let ret_len: *mut u32 = std::mem::transmute(&ret_len);
        if keep_start_function_frame {
            // Obtain current thread's start address
            let ret = raw_syscall!(
                crate::dbj2_hash!(b"NtQueryInformationThread"),
                NtQueryInformationThreadFn,
                -2isize as u64, // GetCurrentThread()
                9u32 as u64,
                thread_information as u64,
                thread_info_len as u64,
                ret_len as u64,
            )
            .unwrap_or(-1);

            if ret == 0 {
                let thread_information = thread_information as *mut usize;

                let function_address: *const u8 = *thread_information as _;
                let mut module_handle: *mut c_void = std::ptr::null_mut();

                let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
                let ntdll_base =
                    get_loaded_module_by_hash(ntdll_hash).unwrap_or(std::ptr::null_mut());

                let ldr_get_ptr = crate::syscall::common::pe::get_export_by_hash(
                    ntdll_base,
                    crate::dbj2_hash!(b"LdrGetDllHandleByAddress"),
                )
                .unwrap();
                let ldr_get_dll_handle_by_address: LdrGetDllHandleByAddressFn =
                    std::mem::transmute(ldr_get_ptr);

                // Determine the module where the current thread's start function is located at.
                let status = ldr_get_dll_handle_by_address(
                    function_address as *mut c_void,
                    &mut module_handle,
                );

                if status == 0 {
                    let base_address = module_handle as usize;
                    let function_addresses = crate::syscall::common::pe::get_function_size(
                        base_address,
                        function_address as _,
                    );
                    start_address = function_addresses.0;
                    end_address = function_addresses.1;
                }
            }
        }

        let mut stack_iterator: *mut usize = current_rsp as *mut usize;
        let mut found = false;

        while !found {
            // Check whether the value stored in this stack's address is located at current thread's start function or
            // BaseThreadInitThunk. Otherwise, iterate to the next word in the stack and repeat the process.
            if (*stack_iterator > start_address && *stack_iterator < end_address)
                || (*stack_iterator > base_thread_init_thunk_start as usize
                    && *stack_iterator < base_thread_init_thunk_end)
            {
                addr = stack_iterator as usize;
                let data = tls_get_value(TLS_INDEX) as *mut usize;
                *data = addr;
                found = true;
            }

            stack_iterator = stack_iterator.add(1);
        }

        addr
    }
}

// TLS is used to store the main module's/BaseThreadInitThunk's frame top address in the stack.
// This allows to efficiently concatenate the spoofing process as many times as needed.
pub fn get_cookie_value() -> usize {
    unsafe {
        let k32 = get_loaded_module_by_hash(crate::dbj2_hash!(b"kernel32.dll"))
            .unwrap_or(std::ptr::null_mut());

        if TLS_INDEX == 0 {
            let tls_alloc_ptr =
                crate::syscall::common::pe::get_export_by_hash(k32, crate::dbj2_hash!(b"TlsAlloc"))
                    .unwrap();
            let tls_alloc: TlsAllocFn = std::mem::transmute(tls_alloc_ptr);
            let r = tls_alloc();
            if r == TLS_OUT_OF_INDEXES {
                return 0;
            }

            TLS_INDEX = r;
        }

        let tls_get_value_ptr =
            crate::syscall::common::pe::get_export_by_hash(k32, crate::dbj2_hash!(b"TlsGetValue"))
                .unwrap();
        let tls_get_value: TlsGetValueFn = std::mem::transmute(tls_get_value_ptr);

        let value = tls_get_value(TLS_INDEX) as *mut usize;
        if value as usize == 0 {
            let local_alloc_ptr = crate::syscall::common::pe::get_export_by_hash(
                k32,
                crate::dbj2_hash!(b"LocalAlloc"),
            )
            .unwrap();
            let local_alloc: LocalAllocFn = std::mem::transmute(local_alloc_ptr);
            let heap_region = local_alloc(0x0040, 8); // 0x0040 = LPTR

            if heap_region != std::ptr::null_mut() {
                let tls_set_value_ptr = crate::syscall::common::pe::get_export_by_hash(
                    k32,
                    crate::dbj2_hash!(b"TlsSetValue"),
                )
                .unwrap();
                let tls_set_value: TlsSetValueFn = std::mem::transmute(tls_set_value_ptr);
                let _ = tls_set_value(TLS_INDEX, heap_region);
            }

            return 0;
        }

        *value
    }
}
