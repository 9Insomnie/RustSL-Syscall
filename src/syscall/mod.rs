#![allow(dead_code, unused_imports)]

pub mod common;
pub use common::*;

#[cfg(feature = "hells_halos_tartarus_gate")]
mod hells_halos_tartarus_gate;
#[cfg(feature = "hells_halos_tartarus_gate")]
pub use hells_halos_tartarus_gate::hells_halos_tartarus_gate as get_syscall;

#[cfg(feature = "freshycalls_syswhispers")]
mod freshycalls_syswhispers;
#[cfg(feature = "freshycalls_syswhispers")]
pub use freshycalls_syswhispers::freshycalls_syswhispers as get_syscall;

#[cfg(feature = "hw_syscall")]
pub mod hw_syscall;
#[cfg(feature = "hw_syscall")]
pub use hw_syscall::get_hw_syscall as get_syscall;

#[cfg(feature = "kfd_syscall")]
pub mod kfd_syscall;
#[cfg(feature = "kfd_syscall")]
pub use kfd_syscall::get_kfd_syscall as get_syscall;

#[macro_export]
macro_rules! syscall {
    ($func_hash:expr, $fn_type:ty, $($arg:expr),* $(,)?) => {
        unsafe {
            let ntdll_hash = $crate::dbj2_hash!(b"ntdll.dll");
            let ntdll_base = $crate::syscall::common::get_loaded_module_by_hash(ntdll_hash);

            if let Some(base) = ntdll_base {
                #[cfg(any(feature = "freshycalls_syswhispers", feature = "hells_halos_tartarus_gate"))]
                {
                    if let Some(data) = $crate::syscall::get_syscall(base, $func_hash) {
                        use $crate::syscall::common::ToSyscallArg;
                        let args = [$($arg.to_arg()),*];
                        let result = $crate::syscall::common::direct_invoke_generic(
                            &data,
                            &args
                        );
                        Some(result as i32)
                    } else {
                        None
                    }
                }

                #[cfg(any(feature = "hw_syscall", feature = "kfd_syscall"))]
                {
                    if let Some(addr) = $crate::syscall::get_syscall(base, $func_hash) {
                        let func: $fn_type = core::mem::transmute(addr);
                        Some(func($($arg),*))
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        }
    };
}