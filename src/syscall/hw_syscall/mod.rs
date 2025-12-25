#![allow(non_snake_case, unused)]
pub mod state;
pub mod handler;
pub mod lifecycle;

use std::sync::atomic::Ordering;
pub use self::state::*;
pub use self::handler::*;
pub use self::lifecycle::*;

pub unsafe fn get_hw_syscall(
    _module_base: *mut u8,
    module_hash: u32,
) -> Option<*mut u8> {
    // #[cfg(feature = "debug")]
    // crate::utils::print_message(&format!("HWSyscalls: Resolving hash {:#x}", module_hash));
    
    // store the requested hash in an atomic so VEH reads a stable value
    TARGET_HASH.store(module_hash, Ordering::SeqCst);
    
    let function_address = prepare_syscall(module_hash);
    
    // clear the target hash to avoid stale values
    TARGET_HASH.store(0, Ordering::SeqCst);

    if function_address == 0 { return None; }
    Some(function_address as *mut u8)
}
