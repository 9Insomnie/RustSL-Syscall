use crate::syscall;
use crate::ntapi::def::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, SECTION_ALL_ACCESS, SEC_COMMIT};
use super::types::*;
use core::ffi::c_void;
use obfstr::obfstr;

pub fn alloc_virtual_memory(size: usize, protection: u32) -> Result<*mut u8, String> {
	alloc_virtual_memory_at(-1, 0, size, protection).map(|addr| addr as *mut u8)
}

pub fn alloc_virtual_memory_at(process_handle: isize, base_addr: usize, size: usize, protection: u32) -> Result<usize, String> {
	let mut base_ptr = base_addr as *mut c_void;
	let mut region = size;
	let nt_alloc_hash = crate::dbj2_hash!(b"NtAllocateVirtualMemory");

	let result = syscall!(
		nt_alloc_hash,
		NtAllocateVirtualMemoryFn,
		process_handle as u64,
		(&mut base_ptr as *mut *mut c_void as u64),
		0usize as u64,
		(&mut region as *mut usize as u64),
		(MEM_COMMIT | MEM_RESERVE) as u64,
		protection as u64
	);

	match result {
		Some(status) if status >= 0 => Ok(base_ptr as usize),
		Some(status) => Err(format!("NTSTATUS error: {:#x}", status)),
		None => Err(obfstr!("Failed to resolve or execute syscall").to_string()),
	}
}

pub fn create_section(size: usize, protection: u32) -> Result<isize, String> {
	let mut section_handle: isize = 0;
	let mut max_size: i64 = size as i64;
	let nt_create_hash = crate::dbj2_hash!(b"NtCreateSection");

	let create_status = syscall!(
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
	.ok_or_else(|| obfstr!("Failed to resolve NtCreateSection").to_string())?;

	if create_status != 0 {
		return Err(format!("NtCreateSection failed: 0x{:x}", create_status));
	}

	Ok(section_handle)
}

pub fn protect_virtual_memory(process_handle: isize, base_addr: usize, size: usize, new_prot: u32) -> Result<u32, String> {
    let nt_protect_hash = crate::dbj2_hash!(b"NtProtectVirtualMemory");
    let mut old_prot = 0;
    let mut base_ptr = base_addr as *mut c_void;
    let mut region_size = size;

    let result = syscall!(
        nt_protect_hash,
        NtProtectVirtualMemoryFn,
        process_handle as u64,
        (&mut base_ptr as *mut *mut c_void as u64),
        (&mut region_size as *mut usize as u64),
        new_prot as u64,
        (&mut old_prot as *mut u32 as u64)
    );

    match result {
        Some(status) if status >= 0 => Ok(old_prot),
        Some(status) => Err(format!("NTSTATUS error: {:#x}", status)),
        None => Err(obfstr!("Failed to resolve or execute syscall").to_string()),
    }
}

pub fn map_view_of_section(section_handle: isize, size: usize, protection: u32) -> Result<*mut u8, String> {
	let mut base_ptr: *mut c_void = core::ptr::null_mut();
	let mut vs = size;
	let nt_map_hash = crate::dbj2_hash!(b"NtMapViewOfSection");

	let map_status = syscall!(
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
	.ok_or_else(|| obfstr!("Failed to resolve NtMapViewOfSection").to_string())?;

	if map_status < 0 || base_ptr.is_null() {
		return Err(obfstr!("NtMapViewOfSection failed").to_string());
	}

	Ok(base_ptr as *mut u8)
}

pub fn unmap_view_of_section(process_handle: isize, base_addr: usize) -> Result<(), String> {
	let nt_unmap_hash = crate::dbj2_hash!(b"NtUnmapViewOfSection");

	let status = syscall!(
		nt_unmap_hash,
		NtUnmapViewOfSectionFn,
		process_handle as u64,
		(base_addr as *mut c_void) as u64
	).ok_or_else(|| obfstr!("Failed to resolve NtUnmapViewOfSection").to_string())?;

	if status < 0 {
		return Err(format!("NtUnmapViewOfSection failed: {:#x}", status));
	}

	Ok(())
}

pub fn free_virtual_memory(process_handle: isize, base_addr: *mut u8, size: usize) -> Result<(), String> {
	let mut base = base_addr as *mut c_void;
	let mut region_size = size;
	let nt_free_hash = crate::dbj2_hash!(b"NtFreeVirtualMemory");

	let status = syscall!(
		nt_free_hash,
		NtFreeVirtualMemoryFn,
		process_handle as u64,
		(&mut base as *mut *mut c_void as u64),
		(&mut region_size as *mut usize as u64),
		MEM_RELEASE as u64
	).ok_or_else(|| obfstr!("Failed to resolve NtFreeVirtualMemory").to_string())?;

	if status < 0 {
		return Err(format!("NtFreeVirtualMemory failed: {:#x}", status));
	}

	Ok(())
}

pub fn read_virtual_memory(process_handle: isize, base_addr: usize, buffer: &mut [u8]) -> Result<usize, String> {
    let mut bytes_read: usize = 0;
    let nt_read_hash = crate::dbj2_hash!(b"NtReadVirtualMemory");

    let status = syscall!(
        nt_read_hash,
        NtReadVirtualMemoryFn,
        process_handle as u64,
        (base_addr as *mut c_void) as u64,
        (buffer.as_mut_ptr() as *mut c_void) as u64,
        buffer.len() as u64,
        (&mut bytes_read as *mut usize as u64)
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("NtReadVirtualMemory failed: {:#x}", status));
    }

    Ok(bytes_read)
}

pub fn write_virtual_memory(process_handle: isize, base_addr: usize, buffer: &[u8]) -> Result<usize, String> {
    let mut bytes_written: usize = 0;
    let nt_write_hash = crate::dbj2_hash!(b"NtWriteVirtualMemory");

    let status = syscall!(
        nt_write_hash,
        NtWriteVirtualMemoryFn,
        process_handle as u64,
        (base_addr as *mut c_void) as u64,
        (buffer.as_ptr() as *mut c_void) as u64,
        buffer.len() as u64,
        (&mut bytes_written as *mut usize as u64)
    ).ok_or_else(|| obfstr!("Syscall failed").to_string())?;

    if status < 0 {
        return Err(format!("NtWriteVirtualMemory failed: {:#x}", status));
    }

    Ok(bytes_written)
}
