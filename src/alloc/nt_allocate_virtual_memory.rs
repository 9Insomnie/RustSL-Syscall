
pub unsafe fn alloc(size: usize) -> Result<*mut u8, String> {
    use crate::api::alloc_virtual_memory;
    use crate::api::PAGE_READWRITE;

    let result = alloc_virtual_memory(size, PAGE_READWRITE);

    match result {
        Ok(ptr) => Ok(ptr),
        Err(e) => Err(e),
    }
}