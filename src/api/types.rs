#![allow(non_snake_case)]

use core::ffi::c_void;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: isize,
    pub object_name: *mut c_void,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub struct ClientId {
    pub unique_process: isize,
    pub unique_thread: isize,
}

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    isize, *mut *mut c_void, usize, *mut usize, u32, u32
) -> i32;

pub type NtCreateSectionFn = unsafe extern "system" fn(
    *mut isize, u32, *mut c_void, *mut i64, u32, u32, isize,
) -> i32;

pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    isize, *mut *mut c_void, *mut usize, u32, *mut u32
) -> i32;

pub type NtMapViewOfSectionFn = unsafe extern "system" fn(
    isize, isize, *mut *mut c_void, usize, usize, *mut i64, *mut usize, u32, u32, u32,
) -> i32;

pub type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    isize, *mut *mut c_void, *mut usize, u32
) -> i32;

pub type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut isize, u32, *mut c_void, isize, *mut c_void, *mut c_void,
    u32, usize, usize, usize, *mut c_void,
) -> i32;

pub type NtWaitForSingleObjectFn = unsafe extern "system" fn(isize, u8, *mut i64) -> i32;

pub type NtCloseFn = unsafe extern "system" fn(isize) -> i32;

pub type NtQueueApcThreadFn = unsafe extern "system" fn(
    isize, *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> i32;

pub type NtQuerySystemInformationFn = unsafe extern "system" fn(
    u32, *mut c_void, u32, *mut u32
) -> i32;

pub type NtTestAlertFn = unsafe extern "system" fn() -> i32;

pub type NtSetContextThreadFn = unsafe extern "system" fn(isize, *const std::ffi::c_void) -> i32;

pub type NtResumeThreadFn = unsafe extern "system" fn(isize, *mut u32) -> i32;

pub type NtOpenProcessFn = unsafe extern "system" fn(
    *mut isize, u32, *mut ObjectAttributes, *mut ClientId
) -> i32;

pub type NtReadVirtualMemoryFn = unsafe extern "system" fn(
    isize, *mut c_void, *mut c_void, usize, *mut usize
) -> i32;

pub type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
    isize, *mut c_void, *mut c_void, usize, *mut usize
) -> i32;

pub type NtDelayExecutionFn = unsafe extern "system" fn(u8, *mut i64) -> i32;

pub type NtQueryInformationProcessFn = unsafe extern "system" fn(
    isize, u32, *mut c_void, u32, *mut u32
) -> i32;

pub type RtlAddVehFn = unsafe extern "system" fn(u32, *mut c_void) -> *mut c_void;

pub type RtlRemoveVehFn = unsafe extern "system" fn(*mut c_void) -> u32;

pub type CreateMailslotAFn = unsafe extern "system" fn(*const u8, u32, u32, *const c_void) -> isize;
pub type GetMailslotInfoFn = unsafe extern "system" fn(isize, *mut u32, *mut u32, *mut u32, *mut u32) -> i32;
pub type CreateFileAFn = unsafe extern "system" fn(*const u8, u32, u32, *const c_void, u32, u32, isize) -> isize;
pub type WriteFileFn = unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const c_void) -> i32;
pub type ReadFileFn = unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *const c_void) -> i32;
pub type CloseHandleFn = unsafe extern "system" fn(isize) -> i32;

pub type NtDuplicateObjectFn = unsafe extern "system" fn(
    isize, isize, isize, *mut isize, u32, u32, u32
) -> i32;

pub type NtQueryObjectFn = unsafe extern "system" fn(
    isize, u32, *mut c_void, u32, *mut u32
) -> i32;

pub type NtSetIoCompletionFn = unsafe extern "system" fn(
    isize, *mut c_void, *mut c_void, i32, usize
) -> i32;
