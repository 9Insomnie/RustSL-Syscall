/// UNWIND_INFO parsing module for dynamic gadget discovery
/// Based on SilentMoonwalk technique by KlezVirus
/// References: Windows x64 exception handling and UNWIND_INFO structures

use windows_sys::Win32::System::{
    Diagnostics::Debug::*,
    SystemServices::*,
};

// Define RUNTIME_FUNCTION if not available
#[repr(C)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

#[repr(C)]
pub struct UnwindInfo {
    pub version_flags: u8,
    pub prolog_size: u8,
    pub unwind_code_count: u8,
    pub frame_register_info: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindCode {
    pub code_offset: u8,
    pub op_info: u8,
}

/// Extract UNWIND_OP (4 bits) and OpInfo (4 bits)
pub fn parse_unwind_code(code: UnwindCode) -> (u8, u8) {
    let op = (code.op_info >> 4) & 0x0F;
    let info = code.op_info & 0x0F;
    (op, info)
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

/// Calculate total stack frame size from UNWIND_INFO
/// Returns the size of stack space allocated by the function prologue
pub unsafe fn calculate_frame_size(unwind_info: *const UnwindInfo) -> Option<usize> {
    if unwind_info.is_null() {
        return None;
    }

    let ui = &*unwind_info;
    let unwind_code_count = ui.unwind_code_count as usize;
    
    if unwind_code_count == 0 {
        return Some(0);
    }

    let mut frame_size: usize = 0;
    let mut idx = 0;
    
    // UNWIND_CODE array starts at offset 4 in UNWIND_INFO
    let unwind_codes_ptr = (unwind_info as *const u8).add(4) as *const UnwindCode;
    let unwind_codes = core::slice::from_raw_parts(unwind_codes_ptr, unwind_code_count as usize);

    while idx < unwind_codes.len() {
        let code = unwind_codes[idx];
        let (op, op_info) = parse_unwind_code(code);

        match op {
            UWOP_PUSH_NONVOL => {
                // Pushes are handled by 'pop' instructions in the epilogue,
                // not by 'add rsp, X'. So we don't add them to the frame_size
                // if we are looking for an 'add rsp, X' gadget.
                idx += 1;
            }
            UWOP_ALLOC_LARGE => {
                if op_info == 0 {
                    // Next USHORT (1 code) is size/8
                    if idx + 1 < unwind_codes.len() {
                        let size_code = *(unwind_codes_ptr.add(idx + 1) as *const u16);
                        frame_size += (size_code as usize) * 8;
                        idx += 2;
                    }
                } else if op_info == 1 {
                    // Next two USHORTs (2 codes) is actual size
                    if idx + 2 < unwind_codes.len() {
                        let ptr = unwind_codes_ptr.add(idx + 1) as *const u32;
                        let size = *ptr as usize;
                        frame_size += size;
                        idx += 3;
                    }
                } else {
                    idx += 1;
                }
            }
            UWOP_ALLOC_SMALL => {
                frame_size += ((op_info + 1) as usize) * 8;
                idx += 1;
            }
            UWOP_SET_FPREG => {
                idx += 1;
            }
            UWOP_SAVE_NONVOL => {
                idx += 2;
            }
            UWOP_SAVE_NONVOL_FAR => {
                idx += 3;
            }
            UWOP_SAVE_XMM128 => {
                idx += 2;
            }
            UWOP_SAVE_XMM128_FAR => {
                idx += 3;
            }
            UWOP_PUSH_MACHFRAME => {
                frame_size += if op_info != 0 { 16 } else { 8 };
                idx += 1;
            }
            _ => {
                idx += 1;
            }
        }
    }

    Some(frame_size)
}

/// Validate that UNWIND_INFO looks legitimate
pub unsafe fn validate_unwind_info(unwind_info: *const UnwindInfo) -> bool {
    if unwind_info.is_null() {
        return false;
    }

    let ui = &*unwind_info;
    
    // Version should be 1 or 3
    let version = ui.version_flags & 0x07;
    if version != 1 && version != 3 {
        return false;
    }

    // Frame register info should be valid
    let frame_reg = ui.frame_register_info & 0x0F;
    if frame_reg >= 16 {
        return false;
    }

    // Unwind code count is u8, max is 255
    // This check is for future-proofing
    #[allow(overflowing_literals)]
    if ui.unwind_code_count as u32 > 255 {
        return false;
    }

    true
}

/// Find 'add rsp, X; ret' gadget pattern dynamically
/// Returns (gadget_address, stack_offset)
pub unsafe fn find_gadget_with_unwind_info(
    image_base: *mut u8,
    rt_functions: *const RuntimeFunction,
    rt_count: usize,
) -> Option<(usize, usize)> {
    if rt_functions.is_null() || rt_count == 0 {
        return None;
    }

    let rt_funcs = core::slice::from_raw_parts(rt_functions, rt_count);

    for rt_func in rt_funcs.iter() {
        let func_start = (image_base as usize) + (rt_func.begin_address as usize);
        let func_end = (image_base as usize) + (rt_func.end_address as usize);
        
        let unwind_info_offset = rt_func.unwind_data as usize;
        let unwind_info = (image_base as usize + unwind_info_offset) as *const UnwindInfo;

        // Validate UNWIND_INFO
        if !validate_unwind_info(unwind_info) {
            continue;
        }

        // Calculate expected frame size
        let frame_size = match calculate_frame_size(unwind_info) {
            Some(size) if size > 0 && size <= 0x100 => size,
            _ => continue,
        };

        // Search for 'add rsp, X; ret' pattern in this function
        // Pattern: 48 83 C4 XX C3 (add rsp, XX; ret)
        let func_size = func_end.saturating_sub(func_start);
        if func_size < 5 {
            continue;
        }

        let func_bytes = core::slice::from_raw_parts(func_start as *const u8, func_size);
        
        for i in 0..(func_size.saturating_sub(4)) {
            if func_bytes[i] == 0x48 
                && func_bytes[i + 1] == 0x83 
                && func_bytes[i + 2] == 0xC4 {
                
                let stack_offset = func_bytes[i + 3] as usize;
                
                // CRITICAL: For SilentMoonwalk, the gadget's stack adjustment MUST match 
                // the function's UNWIND_INFO frame size. 
                // We need a minimum offset to accommodate shadow space (32 bytes), 
                // the gadget address (8 bytes), and potential extra arguments.
                // 0x30 (48 bytes) is safe for up to 6 arguments.
                if stack_offset == frame_size && stack_offset >= 0x30 && (func_bytes[i + 4] == 0xC3) {
                    
                    #[cfg(feature = "debug")]
                    {
                        let gadget_addr = func_start + i;
                        crate::utils::print_message(
                            &format!(
                                "Found valid SilentMoonwalk gadget: {:#x} (offset={:#x})",
                                gadget_addr, stack_offset
                            )
                        );
                    }
                    
                    return Some((func_start + i, stack_offset));
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
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE as u16 {
        return None;
    }

    let nt_headers = (image_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    // Get Exception directory (index 3)
    let exception_dir_entry = &(*nt_headers).OptionalHeader.DataDirectory[3];
    if exception_dir_entry.VirtualAddress == 0 || exception_dir_entry.Size == 0 {
        return None;
    }

    let rt_table = (image_base as usize + exception_dir_entry.VirtualAddress as usize) as *const RuntimeFunction;
    let rt_count = (exception_dir_entry.Size as usize) / core::mem::size_of::<RuntimeFunction>();

    if rt_count == 0 {
        return None;
    }

    Some((rt_table, rt_count))
}
