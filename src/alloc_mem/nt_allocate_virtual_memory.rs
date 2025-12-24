
pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, String> {
    use crate::api::alloc_virtual_memory;
    use crate::api::PAGE_READWRITE;

    let result = alloc_virtual_memory(size, PAGE_READWRITE);

    #[cfg(not(feature = "debug"))]
    for _ in 0..10000 {
        core::hint::spin_loop();
    }

    match result {
        Ok(ptr) => Ok(ptr),
        Err(e) => Err(e),
    }
}