pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("nt_map_view_of_section.alloc_mem: create+map size={}", size));

    use crate::api::PAGE_EXECUTE_READWRITE;

    let section_handle = crate::api::create_section(size, PAGE_EXECUTE_READWRITE)?;
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Section created, handle={:#x}", section_handle));

    let base = crate::api::map_view_of_section(section_handle, size, PAGE_EXECUTE_READWRITE)?;
    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("Section mapped at {:p} (size={})", base, size));

    Ok(base)
}