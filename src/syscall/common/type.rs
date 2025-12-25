use std::ffi::c_void;

/// Configuration struct used by stack spoofing / indirect syscall helpers.
/// Fields mirror the structure expected by the higher-level spoof implementation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Configuration {
    pub god_gadget: usize,
    pub rtl_unwind_address: usize,
    pub rtl_unwind_target: usize,
    pub stub: usize,

    pub first_frame_function_pointer: *mut c_void,
    pub second_frame_function_pointer: *mut c_void,

    pub jmp_rbx_gadget: *mut c_void,
    pub add_rsp_xgadget: *mut c_void,

    pub first_frame_size: usize,
    pub second_frame_size: usize,
    pub jmp_rbx_gadget_frame_size: usize,
    pub add_rsp_xgadget_frame_size: usize,

    pub stack_offset_where_rbp_is_pushed: usize,

    pub spoof_function_pointer: *mut c_void,
    pub return_address: *mut c_void,

    pub nargs: usize,
    pub arg01: *mut c_void,
    pub arg02: *mut c_void,
    pub arg03: *mut c_void,
    pub arg04: *mut c_void,
    pub arg05: *mut c_void,
    pub arg06: *mut c_void,
    pub arg07: *mut c_void,
    pub arg08: *mut c_void,
    pub arg09: *mut c_void,
    pub arg10: *mut c_void,
    pub arg11: *mut c_void,

    pub syscall: u32,
    pub syscall_id: u32,
}


#[derive(Clone, Copy, Debug)]
pub struct SyscallData {
    pub entry: usize,
    pub ssn: u16,
    pub syscall_inst: usize,
}