use crate::syscall;
use crate::api::def::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, SECTION_ALL_ACCESS, SEC_COMMIT};
use super::types::*;

pub fn alloc_virtual_memory(size: usize, protection: u32) -> Result<*mut u8, String> {
	use core::ffi::c_void;
	use obfstr::obfstr;

	let mut base_ptr: *mut c_void = core::ptr::null_mut();
	let mut region = size;
	let nt_alloc_hash = crate::dbj2_hash!(b"NtAllocateVirtualMemory");

	let result = syscall!(
		nt_alloc_hash,
		NtAllocateVirtualMemoryFn,
		-1isize,
		&mut base_ptr,
		0usize,
		&mut region,
		MEM_COMMIT,
		protection
	);

	match result {
		Some(status) if status >= 0 => Ok(base_ptr as *mut u8),
		Some(status) => Err(format!("NTSTATUS error: {:#x}", status)),
		None => Err(obfstr!("Failed to resolve or execute syscall").to_string()),
	}
}

pub fn alloc_virtual_memory_at(process_handle: isize, base_addr: usize, size: usize, protection: u32) -> Result<usize, String> {
	use core::ffi::c_void;
	use obfstr::obfstr;
	use crate::api::def::MEM_RESERVE;

	let mut base_ptr = base_addr as *mut c_void;
	let mut region = size;
	let nt_alloc_hash = crate::dbj2_hash!(b"NtAllocateVirtualMemory");

	let result = syscall!(
		nt_alloc_hash,
		NtAllocateVirtualMemoryFn,
		process_handle,
		&mut base_ptr,
		0usize,
		&mut region,
		MEM_COMMIT | MEM_RESERVE,
		protection
	);

	match result {
		Some(status) if status >= 0 => Ok(base_ptr as usize),
		Some(status) => Err(format!("NTSTATUS error: {:#x}", status)),
		None => Err(obfstr!("Failed to resolve or execute syscall").to_string()),
	}
}

pub fn create_section(size: usize, protection: u32) -> Result<isize, String> {
	use core::ffi::c_void;
	use obfstr::obfstr;

	// constants moved to def.rs

	let mut section_handle: isize = 0;
	let mut max_size: i64 = size as i64;
	let nt_create_hash = crate::dbj2_hash!(b"NtCreateSection");

	let create_status = syscall!(
		nt_create_hash,
		NtCreateSectionFn,
		&mut section_handle,
		SECTION_ALL_ACCESS,
		core::ptr::null_mut(),
		&mut max_size,
		protection,
		SEC_COMMIT,
		0isize
	)
	.ok_or_else(|| obfstr!("Failed to resolve NtCreateSection").to_string())?;

	if create_status != 0 {
		return Err(format!("NtCreateSection failed: 0x{:x}", create_status));
	}

	Ok(section_handle)
}

pub fn protect_virtual_memory(process_handle: isize, base_addr: usize, size: usize, new_prot: u32) -> Result<u32, String> {
    use core::ffi::c_void;
    use obfstr::obfstr;

    let nt_protect_hash = crate::dbj2_hash!(b"NtProtectVirtualMemory");
    let mut old_prot = 0;
    let mut base_ptr = base_addr as *mut c_void;
    let mut region_size = size;

    let result = syscall!(
        nt_protect_hash,
        NtProtectVirtualMemoryFn,
        process_handle,
        &mut base_ptr,
        &mut region_size,
        new_prot,
        &mut old_prot
    );

    match result {
        Some(status) if status >= 0 => Ok(old_prot),
        Some(status) => Err(format!("NTSTATUS error: {:#x}", status)),
        None => Err(obfstr!("Failed to resolve or execute syscall").to_string()),
    }
}

pub fn map_view_of_section(section_handle: isize, size: usize, protection: u32) -> Result<*mut u8, String> {
	use core::ffi::c_void;
	use obfstr::obfstr;

	// PAGE_EXECUTE_READWRITE from def.rs

	let mut base_ptr: *mut c_void = core::ptr::null_mut();
	let mut vs = size;
	let nt_map_hash = crate::dbj2_hash!(b"NtMapViewOfSection");

	let map_status = syscall!(
		nt_map_hash,
		NtMapViewOfSectionFn,
		section_handle,
		-1isize,
		&mut base_ptr,
		0usize,
		0usize,
		core::ptr::null_mut(),
		&mut vs,
		1u32,
		0u32,
		protection
	)
	.ok_or_else(|| obfstr!("Failed to resolve NtMapViewOfSection").to_string())?;

	if map_status < 0 || base_ptr.is_null() {
		return Err(obfstr!("NtMapViewOfSection failed").to_string());
	}

	Ok(base_ptr as *mut u8)
}

pub fn free_virtual_memory(process_handle: isize, base_addr: *mut u8, size: usize) -> Result<(), String> {
	use core::ffi::c_void;
	use obfstr::obfstr;
	use crate::api::def::MEM_RELEASE;

	let mut base = base_addr as *mut c_void;
	let mut region_size = size;
	let nt_free_hash = crate::dbj2_hash!(b"NtFreeVirtualMemory");

	let status = syscall!(
		nt_free_hash,
		NtFreeVirtualMemoryFn,
		process_handle,
		&mut base,
		&mut region_size,
		MEM_RELEASE
	).ok_or_else(|| obfstr!("Failed to resolve NtFreeVirtualMemory").to_string())?;

	if status < 0 {
		return Err(format!("NtFreeVirtualMemory failed: {:#x}", status));
	}

	Ok(())
}

