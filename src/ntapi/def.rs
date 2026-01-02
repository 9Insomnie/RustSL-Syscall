pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
pub const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;
pub const CURRENT_PROCESS: isize = -1isize;
pub const CURRENT_THREAD: isize = -2isize;

pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

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

pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

pub const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

// Process creation flags
pub const PROCESS_CREATE_FLAGS_SUSPENDED: u32 = 0x00000001;
pub const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x00000001;

// PS Create States
pub const PS_CREATE_INITIAL_STATE: u32 = 0;
pub const PS_CREATE_SUCCESS_STATE: u32 = 6;

// PS Attribute types
pub const PS_ATTRIBUTE_IMAGE_NAME: usize = 0x00020005;
pub const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x60008;
pub const PS_ATTRIBUTE_CLIENT_ID: usize = 0x00020006;
pub const PS_ATTRIBUTE_IMAGE_INFO: usize = 0x00020007;

// Protection types
pub const PS_PROTECTED_SIGNER_NONE: u8 = 0;
pub const PS_PROTECTED_TYPE_NONE: u8 = 0;
