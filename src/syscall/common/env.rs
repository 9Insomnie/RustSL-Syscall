use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpebteb::PEB, ntpsapi::PEB_LDR_DATA};
use std::arch::asm;
// 如果你确定要移除 sysinfo 依赖，请在 Cargo.toml 删除，并在此处根据需要实现原生逻辑
use sysinfo::{ProcessExt, SystemExt}; 

pub fn get_process_id_by_name(target_process: &str) -> usize {
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let mut process_id: usize = 0;
    for process in system.processes_by_name(target_process) {
        process_id = process.pid().into();
    }
    process_id
}

#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

pub unsafe fn get_peb() -> *mut PEB {
    (*get_teb()).ProcessEnvironmentBlock
}

pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;
    let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length_chars = ((*module_list).BaseDllName.Length as usize) / 2;
        let dll_name_u16 = core::slice::from_raw_parts(dll_buffer_ptr, dll_length_chars);
        let dll_name_string = String::from_utf16_lossy(dll_name_u16);
        let dll_name_trimmed = dll_name_string.trim_matches(char::from(0));

        if module_hash == crate::utils::dbj2_hash(dll_name_trimmed.as_bytes()) {
            #[cfg(feature = "debug")]
            crate::utils::print_message(&format!("get_loaded_module_by_hash: module matched: base={:p} name={}", (*module_list).DllBase, dll_name_trimmed));
            return Some((*module_list).DllBase as _);
        }
        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }
    None
}