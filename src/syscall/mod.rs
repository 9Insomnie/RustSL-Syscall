#![allow(dead_code, unused_imports)]

pub mod common;
pub use common::*;

#[cfg(feature = "hells_halos_tartarus_gate")]
mod hells_halos_tartarus_gate;
#[cfg(feature = "hells_halos_tartarus_gate")]
pub use hells_halos_tartarus_gate::hells_halos_tartarus_gate as get_syscall;

#[cfg(all(feature = "freshycalls_syswhispers", not(feature = "hells_halos_tartarus_gate")))]
mod freshycalls_syswhispers;
#[cfg(all(feature = "freshycalls_syswhispers", not(feature = "hells_halos_tartarus_gate")))]
pub use freshycalls_syswhispers::freshycalls_syswhispers as get_syscall;

#[cfg(all(feature = "hw_syscall", not(any(feature = "hells_halos_tartarus_gate", feature = "freshycalls_syswhispers"))))]
pub mod hw_syscall;
#[cfg(all(feature = "hw_syscall", not(any(feature = "hells_halos_tartarus_gate", feature = "freshycalls_syswhispers"))))]
pub use hw_syscall::get_hw_syscall as get_syscall;

#[cfg(all(feature = "kfd_syscall", not(any(feature = "hells_halos_tartarus_gate", feature = "freshycalls_syswhispers", feature = "hw_syscall"))))]
pub mod kfd_syscall;
#[cfg(all(feature = "kfd_syscall", not(any(feature = "hells_halos_tartarus_gate", feature = "freshycalls_syswhispers", feature = "hw_syscall"))))]
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
                        let func: $fn_type = core::mem::transmute(data.entry);
                        let args_vec = vec![
                            $(
                                $arg as usize as *mut std::ffi::c_void
                            ),*
                        ];
                        let result = $crate::syscall::common::syscall_with_spoof(data, func as *mut std::ffi::c_void, args_vec);
                        Some(result as i32)
                    } else {
                        None
                    }
                }

                #[cfg(any(feature = "hw_syscall", feature = "kfd_syscall"))]
                {
                    if let Some(addr) = $crate::syscall::get_syscall(base, $func_hash) {
                        let func: $fn_type = core::mem::transmute(addr);
                        // For hw_syscall and kfd_syscall, convert u64 args back to expected types
                        Some(func($($arg as _),*) as i32)
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