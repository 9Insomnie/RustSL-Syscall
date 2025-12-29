use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use crate::syscall::common::pe::get_nt_headers;

#[repr(C)]
#[allow(non_snake_case)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u8,
}

unsafe fn get_section_from_rva(nt_headers: *mut IMAGE_NT_HEADERS64, rva: u32) -> Option<*mut IMAGE_SECTION_HEADER> {
    let optional_header_offset = 24; // Signature (4) + FileHeader (20)
    let size_of_optional_header = (*nt_headers).FileHeader.SizeOfOptionalHeader as usize;
    let first_section = (nt_headers as usize + optional_header_offset + size_of_optional_header) as *mut IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    for i in 0..num_sections {
        let section = first_section.add(i as usize);
        if rva >= (*section).VirtualAddress && rva < (*section).VirtualAddress + (*section).SizeOfRawData {
            return Some(section);
        }
    }
    None
}

unsafe fn is_read_only_pointer(module_base: *mut u8, pointer: *mut c_void) -> bool {
    if pointer.is_null() {
        return false;
    }
    
    let nt_headers = get_nt_headers(module_base);
    if nt_headers.is_none() {
        return false;
    }
    let nt_headers = nt_headers.unwrap();
    
    let image_start = module_base as usize;
    let image_end = image_start + (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let ptr_val = pointer as usize;
    
    if ptr_val < image_start || ptr_val >= image_end {
        return false;
    }
    
    let rva = (ptr_val - image_start) as u32;
    let section = get_section_from_rva(nt_headers, rva);
    
    if let Some(sec) = section {
        return (*sec).Name.starts_with(b".rdata");
    }
    
    false
}

pub unsafe fn return_wow64_function_pointer(module_base: *mut u8) -> Option<*mut c_void> {
    let nt_headers = get_nt_headers(module_base)?;
    let optional_header_offset = 24;
    let size_of_optional_header = (*nt_headers).FileHeader.SizeOfOptionalHeader as usize;
    let first_section = (nt_headers as usize + optional_header_offset + size_of_optional_header) as *mut IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    let target_name = b"Wow64PrepareForException";
    
    for i in 0..num_sections {
        let section = first_section.add(i as usize);
        if (*section).Name.starts_with(b".rdata") {
            let rva = (*section).VirtualAddress;
            let virtual_size = (*section).Misc.VirtualSize;
            let entry_count = (virtual_size as usize - std::mem::size_of::<STRING>()) / std::mem::size_of::<usize>();
            let pointer_array = (module_base as usize + rva as usize) as *mut usize;
            
            for j in 0..entry_count {
                // Use unaligned reads — section data may not be 8-byte aligned
                let ptr_val = std::ptr::read_unaligned(pointer_array.add(j));

                if !is_read_only_pointer(module_base, ptr_val as *mut c_void) {
                    continue;
                }

                let api = ptr_val as *const STRING;
                // Read the STRING structure safely (may be unaligned)
                let api_struct: STRING = std::ptr::read_unaligned(api);

                if api_struct.Length as usize == target_name.len() {
                    if api_struct.Buffer.is_null() {
                        continue;
                    }

                    // SAFETY: buffer points into module .rdata; length is small and validated
                    let buffer = std::slice::from_raw_parts(api_struct.Buffer, target_name.len());
                    if buffer == target_name {
                        // Ensure next pointer exists
                        if j + 1 >= entry_count {
                            continue;
                        }
                        let func_ptr = std::ptr::read_unaligned(pointer_array.add(j + 1));
                        return Some(func_ptr as *mut c_void);
                    }
                }
            }
            break;
        }
    }
    
    None
}
