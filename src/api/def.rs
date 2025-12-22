pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
pub const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;
pub const CURRENT_PROCESS: isize = -1isize;
pub const CURRENT_THREAD: isize = -2isize;

pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_COMMIT: u32 = 0x1000;
pub const SEC_COMMIT: u32 = 0x0800_0000;
pub const SECTION_ALL_ACCESS: u32 = 0xF001F;

pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;

pub const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
