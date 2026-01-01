#![allow(dead_code, unused_imports)]

pub mod common;
pub use common::*;

#[cfg(feature = "hells_halos_tartarus_gate")]
mod hells_halos_tartarus_gate;

#[cfg(feature = "freshycalls_syswhispers")]
mod freshycalls_syswhispers;

#[cfg(feature = "hw_syscall")]
pub mod hw_syscall;

#[cfg(feature = "kfd_syscall")]
pub mod kfd_syscall;

// --- Syscall Trait ---

pub trait SyscallProvider {
    fn resolve(base: *mut u8, hash: u32) -> Option<ResolvedSyscall>;
}

// --- Syscall Providers ---

pub struct HellsGateProvider;
impl SyscallProvider for HellsGateProvider {
    fn resolve(base: *mut u8, hash: u32) -> Option<ResolvedSyscall> {
        #[cfg(feature = "hells_halos_tartarus_gate")]
        unsafe {
            hells_halos_tartarus_gate::hells_halos_tartarus_gate(base, hash)
                .map(ResolvedSyscall::Indirect)
        }
        #[cfg(not(feature = "hells_halos_tartarus_gate"))]
        {
            let _ = (base, hash);
            None
        }
    }
}

pub struct FreshyCallsProvider;
impl SyscallProvider for FreshyCallsProvider {
    fn resolve(base: *mut u8, hash: u32) -> Option<ResolvedSyscall> {
        #[cfg(feature = "freshycalls_syswhispers")]
        return freshycalls_syswhispers::freshycalls_syswhispers(base, hash)
            .map(ResolvedSyscall::Indirect);
        #[cfg(not(feature = "freshycalls_syswhispers"))]
        {
            let _ = (base, hash);
            None
        }
    }
}

pub struct HwSyscallProvider;
impl SyscallProvider for HwSyscallProvider {
    fn resolve(base: *mut u8, hash: u32) -> Option<ResolvedSyscall> {
        #[cfg(feature = "hw_syscall")]
        unsafe {
            hw_syscall::get_hw_syscall(base, hash).map(|p| ResolvedSyscall::Direct(p as usize))
        }
        #[cfg(not(feature = "hw_syscall"))]
        {
            let _ = (base, hash);
            None
        }
    }
}

pub struct KfdSyscallProvider;
impl SyscallProvider for KfdSyscallProvider {
    fn resolve(base: *mut u8, hash: u32) -> Option<ResolvedSyscall> {
        #[cfg(feature = "kfd_syscall")]
        unsafe {
            kfd_syscall::get_kfd_syscall(base, hash).map(|p| ResolvedSyscall::Direct(p as usize))
        }
        #[cfg(not(feature = "kfd_syscall"))]
        {
            let _ = (base, hash);
            None
        }
    }
}

// --- Provider Selection ---

#[cfg(feature = "hells_halos_tartarus_gate")]
pub type CurrentProvider = HellsGateProvider;

#[cfg(all(
    feature = "freshycalls_syswhispers",
    not(feature = "hells_halos_tartarus_gate")
))]
pub type CurrentProvider = FreshyCallsProvider;

#[cfg(all(
    feature = "hw_syscall",
    not(any(
        feature = "hells_halos_tartarus_gate",
        feature = "freshycalls_syswhispers"
    ))
))]
pub type CurrentProvider = HwSyscallProvider;

#[cfg(all(
    feature = "kfd_syscall",
    not(any(
        feature = "hells_halos_tartarus_gate",
        feature = "freshycalls_syswhispers",
        feature = "hw_syscall"
    ))
))]
pub type CurrentProvider = KfdSyscallProvider;

#[cfg(not(any(
    feature = "hells_halos_tartarus_gate",
    feature = "freshycalls_syswhispers",
    feature = "hw_syscall",
    feature = "kfd_syscall"
)))]
pub struct NoProvider;
#[cfg(not(any(
    feature = "hells_halos_tartarus_gate",
    feature = "freshycalls_syswhispers",
    feature = "hw_syscall",
    feature = "kfd_syscall"
)))]
impl SyscallProvider for NoProvider {
    fn resolve(_: *mut u8, _: u32) -> Option<ResolvedSyscall> {
        None
    }
}
#[cfg(not(any(
    feature = "hells_halos_tartarus_gate",
    feature = "freshycalls_syswhispers",
    feature = "hw_syscall",
    feature = "kfd_syscall"
)))]
pub type CurrentProvider = NoProvider;

#[macro_export]
macro_rules! syscall {
    ($func_hash:expr, $fn_type:ty, $($arg:expr),* $(,)?) => {
        {
            use $crate::syscall::SyscallProvider;
            let ntdll_hash = $crate::dbj2_hash!(b"ntdll.dll");
            let ntdll_base = $crate::syscall::common::get_loaded_module_by_hash(ntdll_hash);

            if let Some(base) = ntdll_base {
                match $crate::syscall::CurrentProvider::resolve(base, $func_hash) {
                    Some($crate::syscall::ResolvedSyscall::Indirect(data)) => {
                        let func: $fn_type = core::mem::transmute(data.entry);
                        let args_vec = vec![
                            $(
                                $arg as usize as *mut std::ffi::c_void
                            ),*
                        ];
                        let result = $crate::syscall::common::syscall_with_spoof(data, func as *mut std::ffi::c_void, args_vec);
                        Some(result as i32)
                    }
                    Some($crate::syscall::ResolvedSyscall::Direct(addr)) => {
                        let func: $fn_type = core::mem::transmute(addr);
                        Some(func($($arg as _),*) as i32)
                    }
                    None => None,
                }
            } else {
                None
            }
        }
    };
}
