use crate::api::types::UnicodeString;
use core::ffi::c_void;

#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub unique_process_id: u16,
    pub creator_back_trace_index: u16,
    pub object_type_index: u8,
    pub handle_attributes: u8,
    pub handle_value: u16,
    pub object: *mut c_void,
    pub granted_access: u32,
}

#[repr(C)]
pub struct OBJECT_TYPE_INFORMATION {
    pub type_name: UnicodeString,
    pub total_number_of_objects: u32,
    pub total_number_of_handles: u32,
    pub total_paged_pool_usage: u32,
    pub total_non_paged_pool_usage: u32,
    pub total_name_pool_usage: u32,
    pub total_handle_table_usage: u32,
    pub high_water_number_of_objects: u32,
    pub high_water_number_of_handles: u32,
    pub high_water_paged_pool_usage: u32,
    pub high_water_non_paged_pool_usage: u32,
    pub high_water_name_pool_usage: u32,
    pub high_water_handle_table_usage: u32,
    pub invalid_attributes: u32,
    pub generic_mapping: [u32; 4],
    pub valid_access_mask: u32,
    pub security_required: u8,
    pub maintain_handle_count: u8,
    pub type_index: u8,
    pub reserved_byte: u8,
    pub pool_type: u32,
    pub default_paged_pool_charge: u32,
    pub default_non_paged_pool_charge: u32,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub flink: *mut c_void,
    pub blink: *mut c_void,
}

#[repr(C)]
pub struct TP_TASK {
    pub callbacks: *mut c_void,
    pub numa_node: u32,
    pub ideal_processor: u8,
    pub padding: [u8; 3],
    pub list_entry: LIST_ENTRY,
}

#[repr(C)]
pub struct TP_DIRECT {
    pub task: TP_TASK,
    pub lock: u64,
    pub io_completion_information_list: LIST_ENTRY,
    pub callback: *mut c_void,
    pub numa_node: u32,
    pub ideal_processor: u8,
    pub padding: [u8; 3],
}
