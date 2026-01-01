use crate::syscall;
use super::types::*;
use obfstr::obfstr;

pub fn close_handle(handle: isize) {
    let nt_close_hash = crate::dbj2_hash!(b"NtClose");
    let _ = syscall!(nt_close_hash, NtCloseFn, handle as u64);
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
