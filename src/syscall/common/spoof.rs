#![allow(dead_code, unused_imports)]

use crate::ntapi::def::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, TLS_OUT_OF_INDEXES,
    UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER,
};
use crate::ntapi::types::PVOID;
use crate::syscall::common::pe::{RuntimeFunction, ADD_RSP, JMP_RBX};
use crate::syscall::common::*;
use bitreader::BitReader;
use lazy_static::lazy_static;
use nanorand::{Rng, WyRand};
use obfstr::obfstr;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;
use windows_sys::Win32::System::Threading::GetCurrentThread;

extern "C" {
    pub fn spoof_call(structure: PVOID) -> PVOID;
    pub fn spoof_call2(structure: PVOID) -> PVOID;
    pub fn get_current_rsp() -> usize;
}

#[repr(C)]
pub struct Configuration {
    pub god_gadget: usize,         // Unused atm
    pub rtl_unwind_address: usize, // Unused atm
    pub rtl_unwind_target: usize,  // Unused atm
    pub stub: usize,               // Unused atm
    pub first_frame_function_pointer: PVOID,
    pub second_frame_function_pointer: PVOID,
    pub jmp_rbx_gadget: PVOID,
    pub add_rsp_xgadget: PVOID,
    pub first_frame_size: usize,
    pub second_frame_size: usize,
    pub jmp_rbx_gadget_frame_size: usize,
    pub add_rsp_xgadget_frame_size: usize,
    pub stack_offset_where_rbp_is_pushed: usize,
    pub spoof_function_pointer: PVOID,
    pub return_address: PVOID,
    pub nargs: usize,
    pub arg01: PVOID,
    pub arg02: PVOID,
    pub arg03: PVOID,
    pub arg04: PVOID,
    pub arg05: PVOID,
    pub arg06: PVOID,
    pub arg07: PVOID,
    pub arg08: PVOID,
    pub arg09: PVOID,
    pub arg10: PVOID,
    pub arg11: PVOID,
    pub syscall: u32,
    pub syscall_id: u32,
}

lazy_static! {
    // Original return address -> key
    // Replacement return address -> value
    pub static ref MAP: Arc<Mutex<HashMap<usize,usize>>> = Arc::new(Mutex::new(HashMap::default()));
}

/// Spoof and call with SyscallData for indirect syscall.
pub fn syscall_with_spoof(
    data: crate::syscall::common::SyscallData,
    _func: PVOID,
    args: Vec<PVOID>,
) -> PVOID {
    unsafe {
        let mut config: Configuration = std::mem::zeroed();
        let mut black_list: Vec<(u32, u32)> = vec![];
        let kernelbase = env::get_loaded_module_by_hash(crate::dbj2_hash!(b"kernelbase.dll"))
            .unwrap_or(std::ptr::null_mut()) as usize;

        let mut first_frame_size = 0i32;
        let first_frame_address =
            gadget::find_setfpreg(kernelbase, &mut first_frame_size, &mut black_list);

        let mut push_offset = 0i32;
        let mut second_frame_size = 0i32;
        let second_frame_addr = gadget::find_pushrbp(
            kernelbase,
            &mut second_frame_size,
            &mut push_offset,
            &mut black_list,
        );

        let mut first_gadget_size = 0i32;
        let first_gadget_addr =
            gadget::find_gadget(kernelbase, &mut first_gadget_size, 0, &mut black_list);

        let mut second_gadget_size = 0i32;
        let second_gadget_addr =
            gadget::find_gadget(kernelbase, &mut second_gadget_size, 1, &mut black_list);
        config.first_frame_function_pointer = first_frame_address as *mut _;
        config.first_frame_size = first_frame_size as usize;
        config.second_frame_function_pointer = second_frame_addr as *mut _;
        config.second_frame_size = second_frame_size as usize;
        config.jmp_rbx_gadget = first_gadget_addr as *mut _;
        config.jmp_rbx_gadget_frame_size = first_gadget_size as usize;
        config.add_rsp_xgadget = second_gadget_addr as *mut _;
        config.add_rsp_xgadget_frame_size = second_gadget_size as usize;
        config.stack_offset_where_rbp_is_pushed = push_offset as usize;
        config.spoof_function_pointer = data.syscall_inst as *mut _;
        config.syscall = 1;
        config.syscall_id = data.ssn as u32;

        let keep_start_function_frame = false; // For syscall, default to false

        let mut args_number = args.len();
        config.nargs = args_number;

        while args_number > 0 {
            match args_number {
                11 => config.arg11 = args[args_number - 1],
                10 => config.arg10 = args[args_number - 1],
                9 => config.arg09 = args[args_number - 1],
                8 => config.arg08 = args[args_number - 1],
                7 => config.arg07 = args[args_number - 1],
                6 => config.arg06 = args[args_number - 1],
                5 => config.arg05 = args[args_number - 1],
                4 => config.arg04 = args[args_number - 1],
                3 => config.arg03 = args[args_number - 1],
                2 => config.arg02 = args[args_number - 1],
                1 => config.arg01 = args[args_number - 1],
                _ => (),
            }

            args_number -= 1;
        }

        let mut spoofy = env::get_cookie_value();
        if spoofy == 0 {
            let current_rsp = get_current_rsp();
            spoofy = env::get_desirable_return_address(current_rsp, keep_start_function_frame);
        }

        config.return_address = spoofy as *mut _;
        let config: PVOID = std::mem::transmute(&config);
        spoof_call(config)
    }
}
