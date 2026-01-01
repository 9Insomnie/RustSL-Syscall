use super::types::*;
use crate::ntapi::def::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, SECTION_ALL_ACCESS, SEC_COMMIT,
};
use crate::syscall;
use crate::utils::{RslError, RslResult};
use core::ffi::c_void;
use obfstr::obfstr;

pub fn alloc_virtual_memory(size: usize, protection: u32) -> RslResult<*mut u8> {
    alloc_virtual_memory_at(-1, 0, size, protection).map(|addr| addr as *mut u8)
}

pub fn alloc_virtual_memory_at(
    process_handle: isize,
    base_addr: usize,
    size: usize,
    protection: u32,
) -> RslResult<usize> {
    let mut base_ptr = base_addr as *mut c_void;
    let mut region = size;
    let nt_alloc_hash = crate::dbj2_hash!(b"NtAllocateVirtualMemory");

    let result = unsafe {
        syscall!(
            nt_alloc_hash,
            NtAllocateVirtualMemoryFn,
            process_handle as u64,
            (&mut base_ptr as *mut *mut c_void as u64),
            0usize as u64,
            (&mut region as *mut usize as u64),
            (MEM_COMMIT | MEM_RESERVE) as u64,
            protection as u64
        )
    };

    match result {
        Some(status) if status >= 0 => Ok(base_ptr as usize),
        Some(status) => Err(RslError::NtStatus(status)),
        None => Err(RslError::SyscallFailed(nt_alloc_hash)),
    }
}

pub fn create_section(size: usize, protection: u32) -> RslResult<isize> {
    let mut section_handle: isize = 0;
    let mut max_size: i64 = size as i64;
    let nt_create_hash = crate::dbj2_hash!(b"NtCreateSection");

    let create_status = unsafe {
        syscall!(
            nt_create_hash,
            NtCreateSectionFn,
            (&mut section_handle as *mut isize as u64),
            SECTION_ALL_ACCESS as u64,
            core::ptr::null_mut::<c_void>() as u64,
            (&mut max_size as *mut i64 as u64),
            protection as u64,
            SEC_COMMIT as u64,
            0isize as u64
        )
    };

    match create_status {
        Some(status) if status >= 0 => Ok(section_handle),
        Some(status) => Err(RslError::NtStatus(status)),
        None => Err(RslError::SyscallFailed(nt_create_hash)),
    }
}

pub fn protect_virtual_memory(
    process_handle: isize,
    base_addr: usize,
    size: usize,
    new_prot: u32,
) -> RslResult<u32> {
    let nt_protect_hash = crate::dbj2_hash!(b"NtProtectVirtualMemory");
    let mut old_prot = 0;
    let mut base_ptr = base_addr as *mut c_void;
    let mut region_size = size;

    let result = unsafe {
        syscall!(
            nt_protect_hash,
            NtProtectVirtualMemoryFn,
            process_handle as u64,
            (&mut base_ptr as *mut *mut c_void as u64),
            (&mut region_size as *mut usize as u64),
            new_prot as u64,
            (&mut old_prot as *mut u32 as u64)
        )
    };

    match result {
        Some(status) if status >= 0 => Ok(old_prot),
        Some(status) => Err(RslError::NtStatus(status)),
        None => Err(RslError::SyscallFailed(nt_protect_hash)),
    }
}

pub fn map_view_of_section(
    section_handle: isize,
    size: usize,
    protection: u32,
) -> RslResult<*mut u8> {
    let mut base_ptr: *mut c_void = core::ptr::null_mut();
    let mut vs = size;
    let nt_map_hash = crate::dbj2_hash!(b"NtMapViewOfSection");

    let map_status = unsafe {
        syscall!(
            nt_map_hash,
            NtMapViewOfSectionFn,
            section_handle as u64,
            (-1isize) as u64,
            (&mut base_ptr as *mut *mut c_void as u64),
            0usize as u64,
            0usize as u64,
            core::ptr::null_mut::<i64>() as u64,
            (&mut vs as *mut usize as u64),
            1u32 as u64,
            0u32 as u64,
            protection as u64
        )
    };

    match map_status {
        Some(status) if status >= 0 => {
            if base_ptr.is_null() {
                Err(RslError::Other(
                    obfstr!("NtMapViewOfSection returned null pointer").to_string(),
                ))
            } else {
                Ok(base_ptr as *mut u8)
            }
        }
        Some(status) => Err(RslError::NtStatus(status)),
        None => Err(RslError::SyscallFailed(nt_map_hash)),
    }
}

pub fn unmap_view_of_section(process_handle: isize, base_addr: usize) -> RslResult<()> {
    let nt_unmap_hash = crate::dbj2_hash!(b"NtUnmapViewOfSection");

    let status = unsafe {
        syscall!(
            nt_unmap_hash,
            NtUnmapViewOfSectionFn,
            process_handle as u64,
            (base_addr as *mut c_void) as u64
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(()),
        None => Err(RslError::SyscallFailed(nt_unmap_hash)),
    }
}

pub fn free_virtual_memory(
    process_handle: isize,
    base_addr: *mut u8,
    size: usize,
) -> RslResult<()> {
    let mut base = base_addr as *mut c_void;
    let mut region_size = size;
    let nt_free_hash = crate::dbj2_hash!(b"NtFreeVirtualMemory");

    let status = unsafe {
        syscall!(
            nt_free_hash,
            NtFreeVirtualMemoryFn,
            process_handle as u64,
            (&mut base as *mut *mut c_void as u64),
            (&mut region_size as *mut usize as u64),
            MEM_RELEASE as u64
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(()),
        None => Err(RslError::SyscallFailed(nt_free_hash)),
    }
}

pub fn read_virtual_memory(
    process_handle: isize,
    base_addr: usize,
    buffer: &mut [u8],
) -> RslResult<usize> {
    let mut bytes_read: usize = 0;
    let nt_read_hash = crate::dbj2_hash!(b"NtReadVirtualMemory");

    let status = unsafe {
        syscall!(
            nt_read_hash,
            NtReadVirtualMemoryFn,
            process_handle as u64,
            (base_addr as *mut c_void) as u64,
            (buffer.as_mut_ptr() as *mut c_void) as u64,
            buffer.len() as u64,
            (&mut bytes_read as *mut usize as u64)
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(bytes_read),
        None => Err(RslError::SyscallFailed(nt_read_hash)),
    }
}

pub fn write_virtual_memory(
    process_handle: isize,
    base_addr: usize,
    buffer: &[u8],
) -> RslResult<usize> {
    let mut bytes_written: usize = 0;
    let nt_write_hash = crate::dbj2_hash!(b"NtWriteVirtualMemory");

    let status = unsafe {
        syscall!(
            nt_write_hash,
            NtWriteVirtualMemoryFn,
            process_handle as u64,
            (base_addr as *mut c_void) as u64,
            (buffer.as_ptr() as *mut c_void) as u64,
            buffer.len() as u64,
            (&mut bytes_written as *mut usize as u64)
        )
    };

    match status {
        Some(s) if s < 0 => Err(RslError::NtStatus(s)),
        Some(_) => Ok(bytes_written),
        None => Err(RslError::SyscallFailed(nt_write_hash)),
    }
}
