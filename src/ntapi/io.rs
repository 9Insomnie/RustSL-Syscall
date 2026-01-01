use super::types::*;
use crate::syscall;
use obfstr::obfstr;

pub fn set_io_completion(
    io_completion_handle: isize,
    key_context: *mut core::ffi::c_void,
    apc_context: *mut core::ffi::c_void,
    io_status: i32,
    io_status_information: usize,
) -> crate::utils::error::RslResult<i32> {
    let nt_set_io_hash = crate::dbj2_hash!(b"NtSetIoCompletion");

    let status = unsafe {
        syscall!(
            nt_set_io_hash,
            NtSetIoCompletionFn,
            io_completion_handle as u64,
            key_context as u64,
            apc_context as u64,
            io_status as u64,
            io_status_information as u64
        )
    }
    .ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    Ok(status)
}
