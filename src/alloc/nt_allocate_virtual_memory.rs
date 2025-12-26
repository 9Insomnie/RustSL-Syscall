
pub unsafe fn alloc(size: usize) -> Result<*mut u8, String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Allocating {} bytes via NtAllocateVirtualMemory...", size));

    use crate::api::alloc_virtual_memory;
    use crate::api::PAGE_READWRITE;

    let result = alloc_virtual_memory(size, PAGE_READWRITE);

    match result {
        Ok(ptr) => Ok(ptr),
        Err(e) => Err(e),
    }
}