/// UNWIND_INFO parsing module for dynamic gadget discovery
/// Based on SilentMoonwalk technique by KlezVirus
/// References: Windows x64 exception handling and UNWIND_INFO structures

use windows_sys::Win32::System::{
    Diagnostics::Debug::*,
    SystemServices::*,
};

/// Represents a Windows x64 Runtime Function entry in the Exception Directory
#[repr(C)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

/// Represents the header of the UNWIND_INFO structure
#[repr(C)]
pub struct UnwindInfo {
    pub version_flags: u8,
    pub prolog_size: u8,
    pub unwind_code_count: u8,
    pub frame_register_info: u8,
}

/// Represents a single UNWIND_CODE entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindCode {
    pub code_offset: u8,
    pub op_info: u8,
}

/// UNWIND_OP codes (values for op_info upper 4 bits)
pub const UWOP_PUSH_NONVOL: u8 = 0;
pub const UWOP_ALLOC_LARGE: u8 = 1;
pub const UWOP_ALLOC_SMALL: u8 = 2;
pub const UWOP_SET_FPREG: u8 = 3;
pub const UWOP_SAVE_NONVOL: u8 = 4;
pub const UWOP_SAVE_NONVOL_FAR: u8 = 5;
pub const UWOP_SAVE_XMM128: u8 = 8;
pub const UWOP_SAVE_XMM128_FAR: u8 = 9;
pub const UWOP_PUSH_MACHFRAME: u8 = 10;

/// Extract UNWIND_OP (4 bits) and OpInfo (4 bits) from an UnwindCode
#[inline(always)]
pub fn parse_unwind_code(code: UnwindCode) -> (u8, u8) {
    (code.op_info >> 4, code.op_info & 0x0F)
}

/// Calculate total stack frame size from UNWIND_INFO
/// Returns the size of stack space allocated by the function prologue (sub rsp, X)
pub unsafe fn calculate_frame_size(unwind_info: *const UnwindInfo) -> Option<usize> {
    if unwind_info.is_null() { return None; }

    let ui = &*unwind_info;
    let count = ui.unwind_code_count as usize;
    if count == 0 { return Some(0); }

    let mut frame_size: usize = 0;
    let mut idx = 0;
    
    // UNWIND_CODE array starts at offset 4 in UNWIND_INFO
    let codes_ptr = (unwind_info as *const u8).add(4) as *const UnwindCode;
    let codes = core::slice::from_raw_parts(codes_ptr, count);

    while idx < codes.len() {
        let (op, info) = parse_unwind_code(codes[idx]);

        match op {
            UWOP_PUSH_NONVOL => {
                // Pushes are handled by 'pop' in epilogue, not 'add rsp, X'
                idx += 1;
            }
            UWOP_ALLOC_LARGE => {
                if info == 0 {
                    if idx + 1 < codes.len() {
                        let size = *(codes_ptr.add(idx + 1) as *const u16) as usize * 8;
                        frame_size += size;
                        idx += 2;
                    } else { break; }
                } else if info == 1 {
                    if idx + 2 < codes.len() {
                        let size = *(codes_ptr.add(idx + 1) as *const u32) as usize;
                        frame_size += size;
                        idx += 3;
                    } else { break; }
                } else { idx += 1; }
            }
            UWOP_ALLOC_SMALL => {
                frame_size += (info as usize + 1) * 8;
                idx += 1;
            }
            UWOP_SET_FPREG => idx += 1,
            UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => idx += 2,
            UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => idx += 3,
            UWOP_PUSH_MACHFRAME => {
                frame_size += if info != 0 { 16 } else { 8 };
                idx += 1;
            }
            _ => idx += 1,
        }
    }

    Some(frame_size)
}

/// Validate that UNWIND_INFO looks legitimate for our purposes
pub unsafe fn validate_unwind_info(unwind_info: *const UnwindInfo) -> bool {
    if unwind_info.is_null() { return false; }
    let ui = &*unwind_info;
    
    let version = ui.version_flags & 0x07;
    if version != 1 && version != 3 { return false; }

    let frame_reg = ui.frame_register_info & 0x0F;
    if frame_reg >= 16 { return false; }

    true
}

/// Find 'add rsp, X; ret' gadget pattern dynamically using UNWIND_INFO validation
pub unsafe fn find_gadget_with_unwind_info(
    image_base: *mut u8,
    rt_functions: *const RuntimeFunction,
    rt_count: usize,
) -> Option<(usize, usize)> {
    if rt_functions.is_null() || rt_count == 0 { return None; }
    let rt_funcs = core::slice::from_raw_parts(rt_functions, rt_count);

    for rt_func in rt_funcs.iter() {
        let func_start = (image_base as usize) + (rt_func.begin_address as usize);
        let func_end = (image_base as usize) + (rt_func.end_address as usize);
        let unwind_info = (image_base as usize + rt_func.unwind_data as usize) as *const UnwindInfo;

        if !validate_unwind_info(unwind_info) { continue; }

        let frame_size = match calculate_frame_size(unwind_info) {
            Some(size) if size >= 0x30 && size <= 0x100 => size,
            _ => continue,
        };

        let func_size = func_end.saturating_sub(func_start);
        if func_size < 5 { continue; }

        let bytes = core::slice::from_raw_parts(func_start as *const u8, func_size);
        for i in 0..(func_size.saturating_sub(4)) {
            // Pattern: 48 83 C4 XX C3 (add rsp, XX; ret)
            if bytes[i] == 0x48 && bytes[i+1] == 0x83 && bytes[i+2] == 0xC4 {
                let offset = bytes[i+3] as usize;
                if offset == frame_size && bytes[i+4] == 0xC3 {
                    #[cfg(feature = "debug")]
                    crate::utils::print_message(&format!(
                        "Found SilentMoonwalk gadget: {:#x} (offset={:#x})",
                        func_start + i, offset
                    ));
                    return Some((func_start + i, offset));
                }
            }
        }
    }
    None
}

/// Safely extract runtime function table from PE headers
pub unsafe fn get_runtime_function_table(
    image_base: *mut u8,
) -> Option<(*const RuntimeFunction, usize)> {
    let dos = image_base as *mut IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE as u16 { return None; }

    let nt = (image_base as usize + (*dos).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE { return None; }

    let dir = &(*nt).OptionalHeader.DataDirectory[3]; // Exception Directory
    if dir.VirtualAddress == 0 || dir.Size == 0 { return None; }

    let table = (image_base as usize + dir.VirtualAddress as usize) as *const RuntimeFunction;
    let count = (dir.Size as usize) / core::mem::size_of::<RuntimeFunction>();
    
    if count == 0 { None } else { Some((table, count)) }
}
