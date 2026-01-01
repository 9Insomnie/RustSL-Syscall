pub unsafe fn alloc(size: usize) -> Result<*mut u8, String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Allocating {} bytes via NtMapViewOfSection...", size));

    use crate::ntapi::{PAGE_EXECUTE_READWRITE};
    let section_handle = crate::ntapi::create_section(size, PAGE_EXECUTE_READWRITE)?;

    let base_ptr = crate::ntapi::map_view_of_section(section_handle, size, PAGE_EXECUTE_READWRITE)?;
    
    // Close the section handle as it's no longer needed after mapping
    crate::ntapi::close_handle(section_handle);

    Ok(base_ptr)
}