#![allow(dead_code, unused_imports)]

pub mod pe;
pub mod env;
pub mod scanner;
pub mod ssn;
pub mod hwbp;
pub mod spoof;
pub mod unwind_info;

pub use pe::*;
pub use env::*;
pub use scanner::*;
pub use ssn::*;
pub use hwbp::*;
pub use spoof::*;
pub use unwind_info::*;

pub mod gadget;
pub use gadget::*;

#[derive(Clone, Copy, Debug)]
pub struct SyscallData {
    pub entry: usize,
    pub ssn: u16,
    pub syscall_inst: usize,
}

pub fn is_wow64() -> bool {
    std::mem::size_of::<usize>() == 8
}