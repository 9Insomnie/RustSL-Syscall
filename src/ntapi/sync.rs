use crate::syscall;
use super::types::*;

pub fn wait_for_single_object(handle: isize) -> i32 {
    let nt_wait_hash = crate::dbj2_hash!(b"NtWaitForSingleObject");
    syscall!(nt_wait_hash, NtWaitForSingleObjectFn, handle as u64, 0u8 as u64, core::ptr::null_mut::<i64>() as u64).unwrap_or(-1)
}
