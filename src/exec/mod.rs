#[cfg(feature = "run_nt_create_thread_ex")]
mod create_thread_syscall;
#[cfg(feature = "run_nt_create_thread_ex")]
pub use crate::exec::create_thread_syscall::exec;

#[cfg(feature = "run_apc_syscall")]
mod apc_syscall;
#[cfg(feature = "run_apc_syscall")]
pub use crate::exec::apc_syscall::exec;

#[cfg(feature = "run_hook_bypass")]
mod hook_bypass;
#[cfg(feature = "run_hook_bypass")]
pub use crate::exec::hook_bypass::exec;

#[cfg(feature = "run_early_exception_inject")]
mod early_exception_inject;
#[cfg(feature = "run_early_exception_inject")]
pub use crate::exec::early_exception_inject::exec;

#[cfg(feature = "run_early_cascade")]
mod early_cascade;
#[cfg(feature = "run_early_cascade")]
pub use crate::exec::early_cascade::exec;

#[cfg(feature = "run_entry_point_injection")]
mod entry_point_injection;
#[cfg(feature = "run_entry_point_injection")]
pub use crate::exec::entry_point_injection::exec;

#[cfg(feature = "run_pool_party")]
mod pool_party;
#[cfg(feature = "run_pool_party")]
pub use crate::exec::pool_party::exec;
