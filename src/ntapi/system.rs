use super::types::*;
use crate::syscall;
use crate::utils::NtStatusExt;
use core::ffi::c_void;
use obfstr::obfstr;

pub fn query_system_information(
    info_class: u32,
    buffer: *mut u8,
    size: u32,
    return_len: *mut u32,
) -> crate::utils::error::RslResult<i32> {
    let nt_query_sys_hash = crate::dbj2_hash!(b"NtQuerySystemInformation");

    unsafe {
        syscall!(
            nt_query_sys_hash,
            NtQuerySystemInformationFn,
            info_class as u64,
            (buffer as *mut c_void) as u64,
            size as u64,
            return_len as u64
        )
    }
    .check(nt_query_sys_hash)
}

pub fn delay_execution_seconds(seconds: i64) -> crate::utils::error::RslResult<()> {
    let nt_delay_hash = crate::dbj2_hash!(b"NtDelayExecution");
    let mut interval: i64 = -10_000_000 * seconds; // 100-ns units

    unsafe {
        syscall!(
            nt_delay_hash,
            NtDelayExecutionFn,
            1u8 as u64,
            (&mut interval as *mut i64 as u64)
        )
    }
    .check(nt_delay_hash)?;

    Ok(())
}
