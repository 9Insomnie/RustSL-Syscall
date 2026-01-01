#[cfg(feature = "run_nt_create_thread_ex")]
mod create_thread;
#[cfg(feature = "run_nt_create_thread_ex")]
pub use crate::exec::create_thread::exec;

#[cfg(feature = "run_apc_syscall")]
mod apc;
#[cfg(feature = "run_apc_syscall")]
pub use crate::exec::apc::exec;

#[cfg(feature = "run_hwbp_bypass")]
mod hwbp_bypass;
#[cfg(feature = "run_hwbp_bypass")]
pub use crate::exec::hwbp_bypass::exec;

#[cfg(feature = "run_early_exception_inject")]
mod early_exception;
#[cfg(feature = "run_early_exception_inject")]
pub use crate::exec::early_exception::exec;

#[cfg(feature = "run_early_cascade")]
mod early_cascade;
#[cfg(feature = "run_early_cascade")]
pub use crate::exec::early_cascade::exec;

#[cfg(feature = "run_entry_point_injection")]
mod entry_point;
#[cfg(feature = "run_entry_point_injection")]
pub use crate::exec::entry_point::exec;

#[cfg(feature = "run_process_hollowing")]
mod process_hollowing;
#[cfg(feature = "run_process_hollowing")]
pub use crate::exec::process_hollowing::exec;
