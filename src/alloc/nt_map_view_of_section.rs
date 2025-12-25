pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, String> {
    use crate::api::{PAGE_EXECUTE_READWRITE};
    let section_handle = crate::api::create_section(size, PAGE_EXECUTE_READWRITE)?;

    Ok(crate::api::map_view_of_section(section_handle, size, PAGE_EXECUTE_READWRITE)?)
}