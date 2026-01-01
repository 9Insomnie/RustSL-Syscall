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

pub type NtGetContextThreadFn = unsafe extern "system" fn(isize, *mut std::ffi::c_void) -> i32;

pub type NtSetContextThreadFn = unsafe extern "system" fn(isize, *const std::ffi::c_void) -> i32;

pub type NtResumeThreadFn = unsafe extern "system" fn(isize, *mut u32) -> i32;

pub type NtOpenProcessFn = unsafe extern "system" fn(
    *mut isize, u32, *mut ObjectAttributes, *mut ClientId
) -> i32;

pub type NtOpenProcessTokenFn = unsafe extern "system" fn(
    isize, u32, *mut isize
) -> i32;

pub type NtAdjustPrivilegesTokenFn = unsafe extern "system" fn(
    isize, u8, *mut c_void, u32, *mut c_void, *mut u32
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

pub type NtUnmapViewOfSectionFn = unsafe extern "system" fn(
    isize, *mut c_void
) -> i32;

pub type NtDuplicateObjectFn = unsafe extern "system" fn(
    isize, isize, isize, *mut isize, u32, u32, u32
) -> i32;

pub type NtQueryObjectFn = unsafe extern "system" fn(
    isize, u32, *mut c_void, u32, *mut u32
) -> i32;

pub type NtSetIoCompletionFn = unsafe extern "system" fn(
    isize, *mut c_void, *mut c_void, i32, usize
) -> i32;

pub type NtCreateProcessFn = unsafe extern "system" fn(
    *mut isize, u32, *mut ObjectAttributes, isize, u8, isize, isize, isize
) -> i32;

pub type NtCreateUserProcessFn = unsafe extern "system" fn(
    *mut isize, *mut isize, u32, u32, *mut ObjectAttributes, *mut ObjectAttributes,
    u32, u32, *mut c_void, *mut PsCreateInfo, *mut PsAttributeList
) -> i32;

pub type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
    *mut *mut c_void, *mut UnicodeString, *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, u32
) -> i32;

pub type RtlDestroyProcessParametersFn = unsafe extern "system" fn(*mut c_void) -> i32;

#[repr(C)]
pub struct PsProtection {
    pub signer: u8,
    pub _type: u8,
    pub audit: u8,
    pub _padding: u8,
}

#[repr(C)]
pub struct SectionImageInformation {
    pub transfer_address: *mut c_void,
    pub zero_bits: u32,
    pub maximum_stack_size: usize,
    pub committed_stack_size: usize,
    pub sub_system_type: u32,
    pub sub_system_minor_version: u16,
    pub sub_system_major_version: u16,
    pub sub_system_version: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub image_characteristics: u16,
    pub dll_characteristics: u16,
    pub machine: u16,
    pub image_contains_code: u8,
    pub image_flags: u8,
    pub loader_flags: u32,
    pub image_file_size: u32,
    pub check_sum: u32,
}

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: isize,
    pub console_flags: u32,
    pub standard_input: isize,
    pub standard_output: isize,
    pub standard_error: isize,
    pub current_directory_path: UnicodeString,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: *mut c_void,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UnicodeString,
    pub desktop_info: UnicodeString,
    pub shell_info: UnicodeString,
    pub runtime_data: UnicodeString,
    pub current_directories: [UnicodeString; 32],
    pub environment_size: usize,
    pub environment_version: usize,
    pub package_dependency_data: *mut c_void,
    pub process_group_id: u32,
    pub loader_threads: u32,
    pub redshifted: u32,
}

#[repr(C)]
pub struct PsAttribute {
    pub attribute: usize,
    pub size: usize,
    pub value: *mut c_void,
    pub return_length: *mut usize,
}

#[repr(C)]
pub struct PsAttributeList {
    pub total_length: usize,
    pub attributes: [PsAttribute; 1],
}

#[repr(C)]
pub struct PsCreateInfo {
    pub size: usize,
    pub state: u32,
    pub init_state: PsCreateState,
    pub additional_file_access: u32,
}

#[repr(C)]
pub union PsCreateState {
    pub init_state: std::mem::ManuallyDrop<PsCreateInitState>,
    pub fail_state: std::mem::ManuallyDrop<PsCreateFailState>,
    pub success_state: std::mem::ManuallyDrop<PsCreateSuccessState>,
}

#[repr(C)]
pub struct PsCreateInitState {
    pub init_flags: u32,
    pub additional_file_access: u32,
}

#[repr(C)]
pub struct PsCreateFailState {
    pub exit_status: i32,
}

#[repr(C)]
pub struct PsCreateSuccessState {
    pub exit_status: i32,
    pub output_flags: u32,
    pub additional_file_access: u32,
}
