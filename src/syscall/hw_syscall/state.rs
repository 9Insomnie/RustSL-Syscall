use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize};

// --- 全局状态机变量 ---
pub static mut EXCEPTION_HANDLER_HANDLE: *mut core::ffi::c_void = ptr::null_mut();
pub static NTDLL_HANDLE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
pub static RET_GADGET_ADDRESS: AtomicUsize = AtomicUsize::new(0);
pub static NT_FUNCTION_ADDRESS: AtomicUsize = AtomicUsize::new(0);
// Temporary storage for the requested function hash — VEH will read this instead of ctx.Rcx
pub static TARGET_HASH: AtomicU32 = AtomicU32::new(0);
