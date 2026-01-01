use super::*;
use bitreader::BitReader;
use dinvoke_rs::data::{
    RuntimeFunction, ADD_RSP, JMP_RBX, PVOID, TLS_OUT_OF_INDEXES, UNW_FLAG_CHAININFO,
    UNW_FLAG_EHANDLER,
};
use nanorand::{Rng, WyRand};

pub unsafe fn find_gadget_in_module(module_base: *mut u8, pattern: &[u8]) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;
    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    scanner::find_pattern(module_base as *const u8, image_size, pattern)
}

pub unsafe fn find_ret_gadget(module_name_hash: u32) -> Option<usize> {
    let module_base = get_loaded_module_by_hash(module_name_hash)?;
    let pattern = [0x48, 0x83, 0xC4, 0x68, 0xC3];
    find_gadget_in_module(module_base, &pattern).map(|p| p as usize)
}

pub unsafe fn find_suitable_ret_gadget() -> Option<usize> {
    let k32_hash = crate::dbj2_hash!(b"kernel32.dll");
    let kbase_hash = crate::dbj2_hash!(b"kernelbase.dll");

    if let Some(addr) = find_ret_gadget(k32_hash) {
        return Some(addr);
    }
    if let Some(addr) = find_ret_gadget(kbase_hash) {
        return Some(addr);
    }
    None
}

pub unsafe fn find_syscall_gadget(module_base: *mut u8) -> Option<*mut u8> {
    let pattern = [0x0F, 0x05, 0xC3];
    let gadget = find_gadget_in_module(module_base, &pattern);
    gadget
}

// Locate a call instruction in an arbitrary function and return the next instruction's address.
pub fn generate_random_offset(module: usize, runtime_function: RuntimeFunction) -> u32 {
    let start_address = module + runtime_function.begin_addr as usize;
    let end_address = module + runtime_function.end_addr as usize;
    let pattern = vec![0x48, 0xff, 0x15]; // 0x48 0xff 0x15 00 00 00 00 = rex.W call QWORD PTR [rip+0x0]
    let address = find_pattern(start_address, end_address, pattern);

    if address == -1 || address + 7 >= end_address as isize {
        return 0;
    }

    ((address + 7) - module as isize) as u32
}

pub fn find_pattern(mut start_address: usize, end_address: usize, pattern: Vec<u8>) -> isize {
    unsafe {
        while start_address < (end_address - pattern.len()) {
            if *(start_address as *mut u8) == pattern[0] {
                let temp_iterator = start_address as *mut u8;
                let mut found = true;
                for i in 1..pattern.len() {
                    if *temp_iterator.add(i) != pattern[i] {
                        found = false;
                        break;
                    }
                }

                if found {
                    return start_address as isize;
                }
            }

            start_address += 1;
        }

        -1
    }
}

// Function used to find the JMP RBX and ADD RSP gadgets.
pub fn find_gadget(
    module: usize,
    gadget_frame_size: &mut i32,
    arg: i32,
    black_list: &mut Vec<(u32, u32)>,
) -> usize {
    unsafe {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == std::ptr::null_mut() {
            return 0;
        }

        let items = exception_directory.1 / 12;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items / 2));
        rt = rt.add(rt_offset as usize);
        let mut count = rt_offset;
        while count < items {
            let mut function_start_address = (module + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (module + (*rt).end_addr as usize) as *mut u8;
            let item = ((*rt).begin_addr, (*rt).end_addr);
            if black_list.contains(&item) {
                rt = rt.add(1);
                count += 1;
                continue;
            }

            while (function_start_address as usize) < (function_end_address as usize) - 3 {
                let u16_val = std::ptr::read_unaligned(function_start_address as *const u16);
                let u32_val = std::ptr::read_unaligned(function_start_address as *const u32);
                let next_byte = *function_start_address.add(4);
                if (u16_val == JMP_RBX && arg == 0)
                    || (u32_val == ADD_RSP && next_byte == 0xc3 && arg == 1)
                {
                    *gadget_frame_size = get_frame_size_normal(module, *rt, false, &mut false);
                    if *gadget_frame_size == 0 {
                        function_start_address = function_start_address.add(1);
                        continue;
                    } else {
                        black_list.push(item);
                        return function_start_address as usize;
                    }
                }

                function_start_address = function_start_address.add(1);
            }

            rt = rt.add(1);
            count += 1;
        }

        0
    }
}

// Find a function with a setfpreg unwind code.
pub fn find_setfpreg(
    module: usize,
    frame_size: &mut i32,
    black_list: &mut Vec<(u32, u32)>,
) -> usize {
    unsafe {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == std::ptr::null_mut() {
            return 0;
        }

        let items = exception_directory.1 / 12;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items / 2));
        rt = rt.add(rt_offset as usize);
        let mut count = rt_offset;
        while count < items {
            let runtime_function = *rt;
            let mut found = false;
            *frame_size = get_frame_size_with_setfpreg(module, runtime_function, &mut found);
            if found && *frame_size != 0 {
                let random_offset = generate_random_offset(module, runtime_function);
                if random_offset != 0 {
                    let item = (runtime_function.begin_addr, runtime_function.end_addr);
                    black_list.push(item);
                    return (module + random_offset as usize) as _;
                }
            }

            rt = rt.add(1);
            count += 1;
        }

        0
    }
}

// Find a function where RBP is pushed to the stack.
pub fn find_pushrbp(
    module: usize,
    frame_size: &mut i32,
    push_offset: &mut i32,
    black_list: &mut Vec<(u32, u32)>,
) -> usize {
    unsafe {
        let exception_directory = get_runtime_table(module as *mut _);
        let mut rt = exception_directory.0;
        if rt == std::ptr::null_mut() {
            return 0;
        }

        let items = exception_directory.1 / 12;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items / 2));
        rt = rt.add(rt_offset as usize);
        let mut count = rt_offset;
        while count < items {
            let runtime_function = *rt;
            let item = (runtime_function.begin_addr, runtime_function.end_addr);
            let mut found: bool = false;
            *push_offset = 0;
            *frame_size = 0i32;
            get_frame_size_with_push_rbp(
                module,
                runtime_function,
                &mut found,
                push_offset,
                frame_size,
            );
            if found && *frame_size >= *push_offset && !black_list.contains(&item) {
                let random_offset = generate_random_offset(module, runtime_function);
                if random_offset != 0 {
                    black_list.push(item);
                    return (module + random_offset as usize) as _;
                }
            }

            rt = rt.add(1);
            count += 1;
        }

        0
    }
}

pub fn get_frame_size_normal(
    module: usize,
    runtime_function: RuntimeFunction,
    ignore_rsp_and_bp: bool,
    base_pointer: &mut bool,
) -> i32 {
    unsafe {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let version_and_flags = (*unwind_info).to_ne_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap();
        let unwind_codes_count = *(unwind_info.add(2));

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let mut unwind_code = (unwind_info.add(4)) as *mut u8;
        let mut unwind_code_operation_code_info = unwind_code.add(1);
        // This counter stores the size of the stack frame in bytes.
        let mut frame_size = 0;
        let mut index = 0;
        while index < unwind_codes_count {
            let operation_code_and_info = (*unwind_code_operation_code_info).to_ne_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);

            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            match operation_code {
                0 => {
                    // UWOP_PUSH_NONVOL

                    // operation_info == 4 -> RSP
                    if operation_code == 4 && !ignore_rsp_and_bp {
                        return 0;
                    }

                    frame_size += 8;
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if operation_info == 0 {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        frame_size += size as i32 * 8;

                        unwind_code = unwind_code.add(2);
                        index += 1;
                    } else if operation_info == 1 {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 =
                            (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32) << 16;
                        frame_size += size + size2;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 => {
                    // UWOP_ALLOC_SMALL
                    frame_size += (operation_info * 8 + 8) as i32;
                }
                3 => {
                    // UWOP_SET_FPREG // Dynamic alloc "does not change" frame's size
                    *base_pointer = true; // This is not used atm
                    if !ignore_rsp_and_bp {
                        return 0; // This is meant to prevent the use of return addresses corresponding to functions that set a base pointer
                    }
                }
                4 => {
                    // UWOP_SAVE_NONVOL
                    // operation_info == 4 -> RSP
                    if operation_info == 4 && !ignore_rsp_and_bp {
                        return 0;
                    }

                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 => {
                    // UWOP_SAVE_NONVOL_FAR
                    // operation_info == 4 -> RSP
                    if operation_info == 4 && !ignore_rsp_and_bp {
                        return 0;
                    }

                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                8 => {
                    // UWOP_SAVE_XMM128
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                9 => {
                    // UWOP_SAVE_XMM128_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 => {
                    // UWOP_PUSH_MACH_FRAME
                    if operation_info == 0 {
                        frame_size += 64; // 0x40h
                    } else if operation_code == 1 {
                        frame_size += 72; // 0x48h
                    }
                }
                _ => {}
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & UNW_FLAG_CHAININFO) != 0 {
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }

            let runtime_function: *mut RuntimeFunction = std::mem::transmute(unwind_code);
            let result =
                get_frame_size_normal(module, *runtime_function, ignore_rsp_and_bp, base_pointer);

            frame_size += result as i32;
        }

        frame_size
    }
}

pub fn get_frame_size_with_setfpreg(
    module: usize,
    runtime_function: RuntimeFunction,
    found: &mut bool,
) -> i32 {
    unsafe {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let fp_info = unwind_info.add(3);
        let frame_register_and_offset = (*fp_info).to_ne_bytes().clone(); // Little endian

        let mut reader = BitReader::new(&frame_register_and_offset);
        let frame_register_offset = reader.read_u8(4).unwrap();
        let frame_register = reader.read_u8(4).unwrap();

        let version_and_flags = (*unwind_info).to_ne_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap();

        let unwind_codes_count = *(unwind_info.add(2));

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let mut unwind_code = (unwind_info.add(4)) as *mut u8;
        let mut unwind_code_operation_code_info = unwind_code.add(1);

        let mut frame_size = 0;
        let mut index = 0;
        while index < unwind_codes_count {
            let operation_code_and_info = (*unwind_code_operation_code_info).to_ne_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);

            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            match operation_code {
                0 => {
                    // UWOP_PUSH_NONVOL

                    if operation_info == 4 && !*found {
                        return 0;
                    }

                    frame_size += 8;
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if operation_info == 0 {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        frame_size += size as i32 * 8;

                        unwind_code = unwind_code.add(2);
                        index += 1;
                    } else if operation_info == 1 {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 =
                            (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32) << 16;
                        frame_size += size + size2;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 => {
                    // UWOP_ALLOC_SMALL
                    frame_size += (operation_info * 8 + 8) as i32;
                }
                3 => {
                    // UWOP_SET_FPREG
                    if (flags & UNW_FLAG_EHANDLER) != 0 && (flags & UNW_FLAG_CHAININFO) != 0 {
                        *found = false;
                        return 0;
                    }

                    // This checks if the register used as FP is RBP
                    if frame_register != 5 {
                        *found = false;
                        return 0;
                    }

                    *found = true;
                    let offset = 16 * frame_register_offset;
                    frame_size -= offset as i32;
                }
                4 => {
                    // UWOP_SAVE_NONVOL
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 => {
                    // UWOP_SAVE_NONVOL_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                8 => {
                    // UWOP_SAVE_XMM128
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                9 => {
                    // UWOP_SAVE_XMM128_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 => {
                    // UWOP_PUSH_MACH_FRAME
                    if operation_info == 0 {
                        frame_size += 64; // 0x40h
                    } else if operation_code == 1 {
                        frame_size += 72; // 0x48h
                    }
                }
                _ => {}
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & UNW_FLAG_CHAININFO) != 0 {
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }

            let runtime_function: *mut RuntimeFunction = std::mem::transmute(unwind_code);
            let result = get_frame_size_with_setfpreg(module, *runtime_function, found);

            frame_size += result as i32;
        }

        frame_size
    }
}

pub fn get_frame_size_with_push_rbp(
    module: usize,
    runtime_function: RuntimeFunction,
    found: &mut bool,
    push_offset: &mut i32,
    frame_size: &mut i32,
) {
    unsafe {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let version_and_flags = (*unwind_info).to_ne_bytes().clone();
        let mut reader = BitReader::new(&version_and_flags);

        // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
        let flags = reader.read_u8(5).unwrap();
        let unwind_codes_count = *(unwind_info.add(2));

        // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
        // and Frame Register + Frame Register offset.
        // This way we reach the Unwind codes array.
        let mut unwind_code = (unwind_info.add(4)) as *mut u8;
        let mut unwind_code_operation_code_info = unwind_code.add(1);

        let mut index = 0;
        while index < unwind_codes_count {
            let operation_code_and_info = (*unwind_code_operation_code_info).to_ne_bytes().clone();
            let mut reader = BitReader::new(&operation_code_and_info);

            let operation_info = reader.read_u8(4).unwrap(); // operation info
            let operation_code = reader.read_u8(4).unwrap(); // operation code

            match operation_code {
                0 => {
                    // UWOP_PUSH_NONVOL

                    // operation_info == 4 -> RSP
                    if operation_code == 4 {
                        *found = false;
                        *frame_size = 0;
                        return;
                    }

                    // operation_info == 5 -> RBP
                    if operation_info == 5 {
                        if *found {
                            *found = false;
                            *frame_size = 0;
                            return;
                        }

                        *push_offset = *frame_size;
                        *found = true;
                    }

                    *frame_size += 8;
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if operation_info == 0 {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut i16);
                        *frame_size += size as i32 * 8;

                        unwind_code = unwind_code.add(2);
                        index += 1;
                    } else if operation_info == 1 {
                        let size = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let size2 =
                            (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32) << 16;
                        *frame_size += size + size2;

                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 => {
                    // UWOP_ALLOC_SMALL
                    *frame_size += (operation_info * 8 + 8) as i32;
                }
                3 => {
                    // UWOP_SET_FPREG
                    *found = false;
                    *frame_size = 0;
                    return;
                }
                4 => {
                    // UWOP_SAVE_NONVOL

                    if operation_info == 4 {
                        *found = false;
                        *frame_size = 0;
                        return;
                    }

                    // operation_info == 5 -> RBP
                    if operation_info == 5 {
                        if *found {
                            *found = false;
                            *frame_size = 0;
                            return;
                        }

                        // The scaled-by-8 offset is stored in the next unwind code, which is a short (2 bytes)
                        let offset =
                            *(unwind_code_operation_code_info.add(1) as *mut u16) as i32 * 8;
                        *push_offset = *frame_size + offset;
                        *found = true;
                    }

                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 => {
                    // UWOP_SAVE_NONVOL_FAR

                    if operation_info == 4 {
                        *found = false;
                        *frame_size = 0;
                        return;
                    }

                    // operation_info == 5 -> RBP
                    if operation_info == 5 {
                        if *found {
                            *found = false;
                            *frame_size = 0;
                            return;
                        }

                        let offset1 = *(unwind_code_operation_code_info.add(1) as *mut u16) as i32;
                        let offset2 =
                            (*(unwind_code_operation_code_info.add(3) as *mut u16) as i32) << 16;
                        let offset = offset1 + offset2;
                        *push_offset = *frame_size + offset;
                        *found = true;
                    }

                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                8 => {
                    // UWOP_SAVE_XMM128
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                9 => {
                    // UWOP_SAVE_XMM128_FAR
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 => {
                    // UWOP_PUSH_MACH_FRAME
                    if operation_info == 0 {
                        *frame_size += 64; // 0x40
                    } else if operation_code == 1 {
                        *frame_size += 72; // 0x48
                    }
                }
                _ => {}
            }

            unwind_code = unwind_code.add(2);
            unwind_code_operation_code_info = unwind_code.add(1);
            index += 1;
        }

        // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
        if (flags & UNW_FLAG_CHAININFO) != 0 {
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }

            let runtime_function: *mut RuntimeFunction = std::mem::transmute(unwind_code);
            get_frame_size_with_push_rbp(module, *runtime_function, found, push_offset, frame_size);
        }
    }
}
