#![allow(dead_code, unused_imports)]

pub mod pe;
pub mod env;
pub mod scanner;
pub mod ssn;
pub mod hwbp;
pub mod spoof;

pub use pe::*;
pub use env::*;
pub use scanner::*;
pub use ssn::*;
pub use hwbp::*;
pub use spoof::*;

pub mod gadget;
pub use gadget::*;

mod r#type;
pub use r#type::*;

pub fn is_wow64() -> bool {
    std::mem::size_of::<usize>() == 8
}