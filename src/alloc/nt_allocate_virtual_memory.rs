use crate::utils::RslResult;

pub unsafe fn alloc(size: usize) -> RslResult<*mut u8> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Allocating {} bytes via NtAllocateVirtualMemory...", size));

    use crate::ntapi::alloc_virtual_memory;
    use crate::ntapi::PAGE_READWRITE;

    alloc_virtual_memory(size, PAGE_READWRITE)
}
